"""Static analysis of Bash tool commands.

Before a command runs, the PreToolUse hook asks this module:

- which existing files and directories the command could read, print, copy,
  link or send, so they can be scanned first;
- whether it sends data off the machine (curl, wget, scp, sftp, rsync, nc,
  ncat, socat, ssh and similar tools, /dev/tcp redirections, network calls
  in inline scripts);
- whether it reads a path that cannot be known without running it (command
  substitution, unknown variables, paths computed inside inline scripts);
- which git commands print repository history (show, log -p, diff, stash
  show -p, grep, archive, cat-file, blame and others) and with which
  arguments;
- whether it creates commits, through `git commit`, an alias, or plumbing;
- whether it changes core.hooksPath;
- which files it writes.

What it follows: cd, pushd, popd, $PWD, $OLDPWD, ~+ and ~-; assignments,
including export, declare, readonly, local and typeset; environment
variables visible to the hook; for-loops over literal words; ANSI-C quoting;
brace expansion; globs; redirections; heredocs and here-strings; bash -c and
eval; command and process substitution (each analysed as a command of its
own); interpreter one-liners and heredoc scripts; git aliases given with -c
or configured in the repository.

What it does not cover: shell is a programming language, so this analysis
cannot be complete. A program or script file that opens files itself
(`python tool.py`, `make`, a test runner) is not analysed. Its standard
output is scanned by the PostToolUse hook, but only after the data has
reached the model's context, and that scan never sees data a command sends
to the network, to another process, or to a file. Paths that cannot be
resolved are reported in `Analysis.unresolved` so the caller can decide
conservatively.
"""

from __future__ import annotations

import glob
import itertools
import os
import re
import shlex
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

SEPARATORS = {";", "&&", "||", "|", "&", "\n", "(", ")", "|&", ";;", "`"}
SHELLS = {"bash", "sh", "zsh", "dash", "ksh"}
WRAPPERS = {"sudo", "env", "nice", "nohup", "time", "command", "exec", "xargs", "timeout", "stdbuf", "builtin"}
KEYWORDS = {"if", "then", "else", "elif", "do", "while", "until", "!", "{", "time"}

# Commands that change or describe files without printing their content. A
# segment run by one of these does not count as reading the files it names
# (so `rm` or `git rm --cached` on a PHI file, the remediation, is allowed).
# cp, mv, ln, install and rsync are handled separately: their sources count
# as reads.
NON_READING = {
    "rm", "ls", "stat", "touch", "chmod", "chown", "shred", "unlink", "mkdir", "rmdir", "cd", "du", "wc",
    "basename", "dirname", "realpath", "test", "[", "echo", "printf", "true", "false", "sleep", "export", "set",
    "unset", "which", "type", "pwd", "date", "whoami", "kill", "pkill", "declare", "readonly", "local", "typeset",
    "pushd", "popd", "alias", "hash", "shift", "wait", "jobs", "umask", "trap", "exit", "return", "break",
    "continue", "nproc", "uname", "hostname", "id",
}
GIT_NON_READING = {
    "rm", "mv", "add", "restore", "reset", "status", "ls-files", "stash", "checkout", "switch", "commit",
    "commit-tree", "update-ref", "write-tree", "merge", "rebase", "cherry-pick", "revert", "branch", "tag",
    "init", "fetch", "pull", "push", "remote", "config", "rev-parse", "worktree", "gc", "log", "show", "diff",
    "whatchanged", "reflog", "grep", "archive", "cat-file", "fast-export", "format-patch", "range-diff",
    "diff-tree", "diff-index", "diff-files", "shortlog", "ls-tree", "rev-list", "describe", "merge-base",
    "show-ref", "symbolic-ref", "for-each-ref", "count-objects", "version", "help", "clean",
}

# Commands that walk directories given as arguments.
RECURSIVE_READERS = {"grep", "egrep", "fgrep", "rg", "ag", "ack", "ack-grep", "find", "tar", "zip", "7z", "zgrep"}
# Recursive by default; searching the working directory when given no path.
ALWAYS_RECURSIVE = {"rg", "ag", "ack", "ack-grep"}
GREP_FAMILY = {"grep", "egrep", "fgrep", "zgrep"}

# Commands that transmit data to another machine.
NETWORK = {
    "curl", "wget", "scp", "sftp", "rsync", "nc", "ncat", "netcat", "socat", "ssh", "telnet", "ftp", "tftp",
    "lftp", "rclone", "aws", "gsutil", "gcloud", "az", "azcopy", "s3cmd", "mail", "mailx", "sendmail", "mutt",
    "http", "https", "xh", "openssl", "smbclient",
}
COPIERS = {"cp", "mv", "ln", "install", "rsync", "scp"}
# Options of copying commands that take a separate value.
COPY_VALUE_OPTS = {
    "install": {"-m", "--mode", "-o", "--owner", "-g", "--group", "-S", "--suffix"},
    "rsync": {"-e", "--rsh", "--exclude", "--include", "--filter", "-f"},
    "scp": {"-P", "-i", "-F", "-l", "-o", "-c", "-J", "-S"},
}

WRITE_WORDS = {
    "tee", "sed", "rm", "mv", "cp", "truncate", "chmod", "chown", "ln", "dd", "install", "shred", "unlink",
    "python", "python3", "perl", "ruby", "node", "deno", "bun", "awk", "gawk", "echo", "printf", "touch",
    "vi", "vim", "nano", "ed", "rsync", "git",
}
# Commands whose operands are the files they modify.
MODIFIERS = {"touch", "truncate", "chmod", "chown", "tee", "shred"}

MAX_EMBEDDED_SCAN = 20_000
MAX_BRACE_EXPANSIONS = 64
MAX_VALUES = 64
MAX_DEPTH = 3
GIT_TIMEOUT = 5

# Markers substituted into the command text before tokenising. They are in a
# Unicode private-use range, so they cannot collide with ordinary text.
LIT_DOLLAR = ""  # a `$` that the shell does not expand (quoted or escaped)
LIT_TICK = ""  # a literal backtick
MARK = ""  # brackets a placeholder: S<n> command substitution, P<n> process substitution, D<n> heredoc
_PLACEHOLDER = re.compile(MARK + r"([SPD])(\d+)" + MARK)

# The plugin's own CLI. Only this file is trusted to run read-only phi-gate
# commands without its arguments being scanned.
PLUGIN_ENTRY = Path(__file__).resolve().parents[2] / "bin" / "phi-gate"
ENTRY_NAME = "phi-gate"

_EMBEDDED_PATH = re.compile(
    r"(?<![\w~./-])(?:[\w~./-]{0,200}[\w-]\.[A-Za-z0-9]{1,8}\b|[\w~.-]{0,200}/[\w~./-]{1,300})"
)
_BRACE = re.compile(r"^(.*?)\{([^{}]*,[^{}]*)\}(.*)$")
_ASSIGN = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)(\+?)=(.*)$", re.S)
_UNEXPANDED = re.compile(r"\$(?:[A-Za-z_{(@*#?!$0-9-])")
_VAR_REF = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?:(:?[-=+?])([^}]*))?\}|\$([A-Za-z_][A-Za-z0-9_]*)")
_HEREDOC = re.compile(r"<<(-?)[ \t]*(?:'([^'\n]*)'|\"([^\"\n]*)\"|\\?([^\s;&|<>()'\"]+))")
# Substitutions whose output is known not to be a file path, or is known.
_SAFE_SUBST = re.compile(
    r"(?:date|whoami|id(?: -[ugn]+)?|nproc|uname(?: -\w+)?|hostname|arch|getconf \w+|tput \w+|"
    r"git rev-parse (?:--short )?HEAD|git branch --show-current|git describe(?: [\w-]+)*)(?:\s+[+\w%:-]*)*"
)


def tokenize(command: str) -> list[str]:
    try:
        lex = shlex.shlex(command.replace("`", " ` "), posix=True, punctuation_chars="();<>|&\n")
        lex.whitespace = " \t\r"
        lex.whitespace_split = True
        return list(lex)
    except ValueError:  # unbalanced quotes: fall back to a crude split
        return re.findall(r"[^\s;&|<>()]+|[;&|<>()\n]+", command)


def segments(tokens: list[str]) -> list[list[str]]:
    return [seg for _, seg in _segments(tokens)]


def _segments(tokens: list[str]) -> list[tuple[str, list[str]]]:
    """Simple commands with the separator that precedes each."""
    out: list[tuple[str, list[str]]] = [("", [])]
    for tok in tokens:
        if tok in SEPARATORS:
            out.append((tok, []))
        else:
            out[-1][1].append(tok)
    return [(sep, s) for sep, s in out if s]


def _lit(word: str) -> str:
    """The word as the program receives it, with literal-dollar markers restored."""
    return word.replace(LIT_DOLLAR, "$").replace(LIT_TICK, "`")


def _expand_vars(word: str, cwd: Path, oldpwd: Path | None = None) -> str:
    home = str(Path.home())
    word = re.sub(r"\$\{PWD\}|\$PWD\b", lambda _m: str(cwd), word)
    word = re.sub(r"\$\{HOME\}|\$HOME\b", lambda _m: home, word)
    if oldpwd is not None:
        word = re.sub(r"\$\{OLDPWD\}|\$OLDPWD\b", lambda _m: str(oldpwd), word)
    if word == "~+" or word.startswith("~+/"):
        word = str(cwd) + word[2:]
    elif oldpwd is not None and (word == "~-" or word.startswith("~-/")):
        word = str(oldpwd) + word[2:]
    elif word == "~" or word.startswith("~/"):
        word = home + word[1:]
    return word


def _expand_braces(word: str) -> list[str]:
    results = [word]
    for _ in range(3):
        nxt: list[str] = []
        changed = False
        for w in results:
            m = _BRACE.match(w)
            if m:
                changed = True
                nxt.extend(m.group(1) + alt + m.group(3) for alt in m.group(2).split(","))
            else:
                nxt.append(w)
        results = nxt[:MAX_BRACE_EXPANSIONS]
        if not changed:
            break
    return results


def _command_word(seg: list[str]) -> tuple[str, int]:
    """Basename of the command a segment runs, skipping VAR=x, keywords and wrappers."""
    i = 0
    while i < len(seg):
        w = seg[i]
        if _ASSIGN.match(w) or w in KEYWORDS:
            i += 1
            continue
        name = os.path.basename(_lit(w))
        if name in WRAPPERS:
            i += 1
            while i < len(seg) and seg[i].startswith("-"):
                i += 1
            if name == "timeout" and i < len(seg):
                i += 1  # the duration
            continue
        return name, i
    return "", len(seg)


@dataclass
class Commit:
    args: list[str]
    bypass: bool = False
    include_all: bool = False
    kind: str = "commit"


@dataclass
class Move:
    sources: list[Path]
    dest: Path


@dataclass
class GitRead:
    """A git command that prints file content from the index or history."""

    sub: str
    args: list[str]
    cwd: Path
    unresolved: bool = False


@dataclass
class Analysis:
    read_files: list[Path] = field(default_factory=list)
    read_dirs: list[Path] = field(default_factory=list)
    commits: list[Commit] = field(default_factory=list)
    stages_changes: bool = False  # `git add` somewhere in the command
    disables_hooks: bool = False
    shows_staged: bool = False  # `git diff --cached` prints staged content
    writes: list[Path] = field(default_factory=list)  # paths a writing command names
    created: list[Path] = field(default_factory=list)  # paths the command certainly creates or modifies
    egress: list[str] = field(default_factory=list)  # how the command sends data off the machine
    unresolved: list[str] = field(default_factory=list)  # reads whose path is known only at run time
    git_reads: list[GitRead] = field(default_factory=list)
    moves: list[Move] = field(default_factory=list)


def commit_flags(args: list[str]) -> tuple[bool, bool]:
    """(bypasses_hooks, includes_unstaged) for `git commit` arguments."""
    bypass = include_all = False
    skip_next = False
    takes_value = {"-m", "--message", "-F", "--file", "-C", "-c", "--author", "--date", "-t", "--template",
                   "--reuse-message", "--reedit-message", "--fixup", "--squash", "--cleanup", "--trailer"}
    for tok in args:
        if skip_next:
            skip_next = False
            continue
        if tok in takes_value:
            skip_next = True
            continue
        if tok.startswith("--"):
            name = tok[2:].split("=", 1)[0]
            if len(name) >= 4 and "no-verify".startswith(name):  # git accepts unambiguous prefixes
                bypass = True
            elif len(name) >= 2 and "all".startswith(name):
                include_all = True
            continue
        if tok.startswith("-") and len(tok) > 1:
            for k, ch in enumerate(tok[1:]):
                if ch in "mFCct":  # option with a value: rest of cluster, or the next token
                    if k == len(tok) - 2:
                        skip_next = True
                    break
                if ch == "n":
                    bypass = True
                if ch == "a":
                    include_all = True
    return bypass, include_all


def _long_no_verify(args: list[str]) -> bool:
    for tok in args:
        if tok == "--":
            break
        name = tok[2:].split("=", 1)[0] if tok.startswith("--") else ""
        if len(name) >= 6 and "no-verify".startswith(name):
            return True
    return False


# --------------------------------------------------------------------------
# Text preparation: quoting, substitutions, heredocs
# --------------------------------------------------------------------------


@dataclass
class _Prepared:
    text: str
    subs: list[str] = field(default_factory=list)
    procs: list[str] = field(default_factory=list)
    docs: list[str] = field(default_factory=list)


_C_ESCAPES = {"a": "\a", "b": "\b", "e": "\x1b", "E": "\x1b", "f": "\f", "n": "\n", "r": "\r", "t": "\t",
              "v": "\v", "\\": "\\", "'": "'", '"': '"', "?": "?"}


def _ansi_c(text: str, start: int) -> tuple[int, str]:
    """Decode the body of $'...' starting at `start`; returns (index after the quote, value)."""
    out: list[str] = []
    i, n = start, len(text)
    while i < n:
        c = text[i]
        if c == "'":
            return i + 1, "".join(out)
        if c != "\\" or i + 1 >= n:
            out.append(c)
            i += 1
            continue
        e = text[i + 1]
        if e in _C_ESCAPES:
            out.append(_C_ESCAPES[e])
            i += 2
        elif e in "xuU":
            width = {"x": 2, "u": 4, "U": 8}[e]
            m = re.match(r"[0-9A-Fa-f]+", text[i + 2:i + 2 + width])
            if m:
                try:
                    out.append(chr(int(m.group(0), 16)))
                except (ValueError, OverflowError):
                    pass
                i += 2 + len(m.group(0))
            else:
                out.append("\\" + e)
                i += 2
        elif e in "01234567":
            m = re.match(r"[0-7]{1,3}", text[i + 1:i + 4])
            assert m is not None
            out.append(chr(int(m.group(0), 8) & 0xFF))
            i += 1 + len(m.group(0))
        elif e == "c" and i + 2 < n:
            out.append(chr(ord(text[i + 2]) & 0x1F))
            i += 3
        else:
            out.append("\\" + e)
            i += 2
    return n, "".join(out)


def _squote(value: str) -> str:
    value = value.replace("$", LIT_DOLLAR).replace("`", LIT_TICK)
    return "'" + value.replace("'", "'\\''") + "'"


def _matching_paren(text: str, open_idx: int) -> int:
    depth = 0
    quote: str | None = None
    k = open_idx
    n = len(text)
    while k < n:
        ch = text[k]
        if quote:
            if ch == "\\" and quote == '"':
                k += 2
                continue
            if ch == quote:
                quote = None
        elif ch == "\\":
            k += 2
            continue
        elif ch in "'\"":
            quote = ch
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return k
        k += 1
    return n


def _prepare(command: str, top: Path | None) -> _Prepared:
    """Rewrite the command so the tokenizer sees what the shell would: literal
    dollars marked, ANSI-C strings decoded, substitutions and heredoc bodies
    replaced by placeholders that refer to their text."""
    prep = _Prepared("")
    out: list[str] = []
    pending: list[tuple[str, bool, int]] = []
    quote: str | None = None
    i, n = 0, len(command)

    def substitution(inner: str) -> str:
        s = inner.strip()
        if s in ("pwd", "pwd -P", "pwd -L"):
            return "$PWD"
        if s == "git rev-parse --show-toplevel" and top is not None:
            return str(top)
        if _SAFE_SUBST.fullmatch(s):
            return "0"
        prep.subs.append(inner)
        return f"{MARK}S{len(prep.subs) - 1}{MARK}"

    while i < n:
        c = command[i]
        if quote == "'":
            if c == "'":
                quote = None
            out.append({"$": LIT_DOLLAR, "`": LIT_TICK}.get(c, c))
            i += 1
            continue
        if c == "\\" and i + 1 < n:
            nxt = command[i + 1]
            if nxt == "\n":
                i += 2
                continue
            if nxt == "$":
                out.append(LIT_DOLLAR)
            elif nxt == "`":
                out.append(LIT_TICK)
            else:
                out.append(command[i:i + 2])
            i += 2
            continue
        if c == "'" and quote is None:
            quote = "'"
            out.append(c)
            i += 1
            continue
        if c == '"':
            quote = None if quote == '"' else '"'
            out.append(c)
            i += 1
            continue
        if c == "$" and i + 1 < n:
            nxt = command[i + 1]
            if nxt == "'" and quote is None:
                i, value = _ansi_c(command, i + 2)
                out.append(_squote(value))
                continue
            if nxt == '"' and quote is None:  # $"..." is a translated string
                i += 1
                continue
            if nxt == "(":
                j = _matching_paren(command, i + 1)
                if command.startswith("$((", i):
                    out.append("0")  # arithmetic expansion
                else:
                    out.append(substitution(command[i + 2:j]))
                i = j + 1
                continue
        if c == "`":
            j = i + 1
            while j < n and command[j] != "`":
                j += 2 if command[j] == "\\" else 1
            out.append(substitution(command[i + 1:j].replace("\\`", "`")))
            i = j + 1
            continue
        if quote is None and c in "<>" and i + 1 < n and command[i + 1] == "(":
            j = _matching_paren(command, i + 1)
            prep.procs.append(command[i + 2:j])
            out.append(f" {MARK}P{len(prep.procs) - 1}{MARK} ")
            i = j + 1
            continue
        if quote is None and command.startswith("<<<", i):
            out.append("<<<")
            i += 3
            continue
        if quote is None and command.startswith("<<", i):
            m = _HEREDOC.match(command, i)
            if m:
                delim = next(g for g in (m.group(2), m.group(3), m.group(4)) if g is not None)
                prep.docs.append("")
                pending.append((delim, m.group(1) == "-", len(prep.docs) - 1))
                out.append(f" < {MARK}D{len(prep.docs) - 1}{MARK} ")
                i = m.end()
                continue
        if c == "\n" and quote is None and pending:
            out.append("\n")
            i += 1
            for delim, strip_tabs, idx in pending:
                body: list[str] = []
                while i < n:
                    e = command.find("\n", i)
                    e = n if e < 0 else e
                    line = command[i:e]
                    i = e + 1
                    if (line.lstrip("\t") if strip_tabs else line) == delim:
                        break
                    body.append(line)
                prep.docs[idx] = "\n".join(body)
            pending = []
            continue
        if c == "#" and quote is None and (i == 0 or command[i - 1] in " \t\n;&|("):
            e = command.find("\n", i)
            i = n if e < 0 else e
            continue
        out.append(c)
        i += 1
    prep.text = "".join(out)
    return prep


# --------------------------------------------------------------------------
# Inline scripts
# --------------------------------------------------------------------------

_INTERPRETER = re.compile(
    r"^(?:(python|pypy)[\d.]*|(node|nodejs|bun|deno)|(perl)[\d.]*|(ruby)[\d.]*|(php)[\d.]*|(Rscript|lua[\d.]*|"
    r"osascript|tclsh)|(awk|gawk|mawk|nawk))$"
)
_LANGS = ("python", "node", "perl", "ruby", "php", "other", "awk")

# Calls whose first argument names a file to open, copy or connect to.
_PATH_CALL = re.compile(
    r"(?<![\w$])(?:open|io\.open|codecs\.open|os\.open|Path|PurePath|PosixPath|pathlib\.Path|readFileSync|"
    r"readFile|createReadStream|openSync|fopen|file_get_contents|readfile|read_csv|read_excel|read_json|"
    r"read_table|read_parquet|read_fwf|read_feather|read_pickle|read_sas|read_stata|loadtxt|genfromtxt|np\.load|numpy\.load|torch\.load|"
    r"connect|copy|copyfile|copy2|copytree|move|File\.read|File\.open|File\.readlines|File\.foreach|IO\.read|"
    r"IO\.readlines|CSV\.read|CSV\.foreach|CSV\.open|Pathname\.new|Bun\.file|Deno\.readTextFile|"
    r"Deno\.readFile)\s*\("
)
# Constructs that reach files whose names are not written in the script.
_COMPUTED = re.compile(
    r"(?<![\w$])(?:os\.walk|os\.listdir|os\.scandir|scandir|listdir|glob|iglob|iterdir|rglob|readdirSync|readdir|"
    r"opendir|Dir\.glob|Dir\.entries|Dir\[|Find\.find|File::Find|os\.path\.join|path\.join|path\.resolve|"
    r"Path\.cwd|Path\.home|subprocess|os\.system|os\.popen|os\.exec\w*|popen|check_output|child_process|"
    r"execSync|spawnSync|exec|eval|system|shell_exec|passthru|proc_open|IO\.popen|Open3|__import__|importlib|"
    r"getline|qx|readlink)\b|<\s*\$|<\*|%x[\(\[{]|`"
)
_NETWORK_API = re.compile(
    r"(?<![\w$])(?:urllib|requests|httpx|http\.client|aiohttp|socket|smtplib|ftplib|paramiko|fetch|XMLHttpRequest|"
    r"axios|https?\.request|https?\.get|net\.connect|net\.Socket|Net::HTTP|LWP|IO::Socket|HTTP::Tiny|curl_exec|"
    r"fsockopen|Deno\.connect|WebSocket)\b"
)
_STRING = re.compile(r"""(?<![\w$])[rRbBuU]{0,2}(?:'(?:[^'\\\n]|\\.)*'|"(?:[^"\\\n]|\\.)*")""")


def _first_argument(script: str, start: int) -> str:
    depth = 0
    out: list[str] = []
    for ch in script[start:start + 2000]:
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth == 0:
                break
            depth -= 1
        elif ch == "," and depth == 0:
            break
        out.append(ch)
    return "".join(out)


def script_access(script: str, lang: str) -> tuple[bool, bool]:
    """(reaches a computed path, uses the network) for an inline script.

    A script reaches only literal paths when every file-opening call takes a
    single string literal (those paths are scanned like any other) and it
    uses nothing that lists directories, joins paths, or runs other programs.
    """
    text = script[:MAX_EMBEDDED_SCAN]
    network = bool(_NETWORK_API.search(text))
    if lang == "awk":
        computed = bool(re.search(r"getline\s*(?:\w+\s*)?<\s*(?![\"'][^\"']*[\"']\s*[);}\n]|[\"'][^\"']*[\"']\s*$)", text)
                        or re.search(r"\bsystem\s*\(|\|\s*getline", text))
        return computed, network
    if _COMPUTED.search(text):
        return True, network
    flat = _STRING.sub("S", text)
    for m in _PATH_CALL.finditer(flat):
        arg = _first_argument(flat, m.end()).strip()
        if lang == "perl" and re.match(r"^(?:my\s+)?[$\w]+$", arg):
            # open(FH, MODE, PATH): every argument after the handle must be literal
            rest = flat[m.end():m.end() + 2000].split(")", 1)[0].split(",")[1:]
            if all(a.strip() in ("S", "") for a in rest):
                continue
            return True, network
        if arg in ("S", "") or arg.isdigit():
            continue
        return True, network
    return False, network


def _inline_scripts(lang: str, args: list[str]) -> tuple[list[str], bool]:
    """(scripts given on the command line, whether stdin is the script)."""
    scripts: list[str] = []
    i = 0
    positional: list[str] = []
    while i < len(args):
        a = args[i]
        nxt = args[i + 1] if i + 1 < len(args) else None
        if lang == "python" and re.fullmatch(r"-[A-Za-z]*c", a) and nxt is not None:
            scripts.append(nxt)
            i += 2
            continue
        if lang == "python" and re.fullmatch(r"-[A-Za-z]*m", a):
            return scripts, False  # runs a module: not analysed
        if lang == "node" and (a in ("-e", "-p", "--eval", "--print", "-pe") or re.fullmatch(r"-[A-Za-z]*[ep]", a)) \
                and nxt is not None:
            scripts.append(nxt)
            i += 2
            continue
        if lang == "node" and a == "eval" and nxt is not None:
            scripts.append(nxt)
            i += 2
            continue
        if lang in ("perl", "ruby") and re.fullmatch(r"-[A-Za-z]*[eE]", a) and nxt is not None:
            scripts.append(nxt)
            i += 2
            continue
        if lang == "php" and a == "-r" and nxt is not None:
            scripts.append(nxt)
            i += 2
            continue
        if lang == "other" and a == "-e" and nxt is not None:
            scripts.append(nxt)
            i += 2
            continue
        if lang == "awk":
            if a == "-f":
                return scripts, False
            if a in ("-F", "-v") and nxt is not None:
                i += 2
                continue
        if not a.startswith("-") or a == "-":
            positional.append(a)
        i += 1
    if lang == "awk" and positional:
        return [positional[0]], False
    stdin_script = not scripts and (not positional or positional[0] == "-")
    return scripts, stdin_script


# --------------------------------------------------------------------------
# git
# --------------------------------------------------------------------------

GIT_GLOBAL_VALUE = {"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--exec-path", "--config-env",
                    "--super-prefix", "--attr-source", "--list-cmds"}
COMMIT_LIKE = {"commit", "commit-tree", "update-ref", "merge", "cherry-pick", "revert", "am", "rebase"}
GIT_BUILTINS = GIT_NON_READING | COMMIT_LIKE | {
    "am", "annotate", "apply", "bisect", "blame", "bundle", "check-attr", "check-ignore", "cherry", "clone",
    "difftool", "fast-import", "fsck", "hash-object", "ls-remote", "mergetool", "notes", "read-tree", "repack",
    "replace", "send-email", "show-branch", "sparse-checkout", "submodule", "update-index", "var",
    "verify-commit", "maintenance", "request-pull", "filter-branch", "unpack-file", "checkout-index",
}
_PATCH_FLAG = re.compile(
    r"^(?:-p|-u|--patch|--patch-with-stat|--patch-with-raw|-U\d*|--unified(?:=\d+)?|--cc|-c|--word-diff.*|"
    r"--color-words.*|-W|--function-context|--binary|--textconv|--ext-diff|-L.*|--full-diff|-m)$"
)
_NO_PATCH_FLAG = re.compile(
    r"^(?:-s|--no-patch|--stat.*|--shortstat|--numstat|--name-only|--name-status|--raw|--summary|--dirstat.*|"
    r"-X.*|--compact-summary|--quiet)$"
)
HISTORY_SUBS = {"bundle", "show", "log", "whatchanged", "reflog", "diff", "diff-tree", "diff-index", "diff-files", "stash",
                "grep", "archive", "cat-file", "blame", "annotate", "fast-export", "format-patch", "range-diff"}

_alias_cache: dict[str, dict[str, str]] = {}


def _parse_git(args: list[str]) -> tuple[list[tuple[str, str]], list[str], str, list[str]]:
    """(-c config pairs, -C directories, subcommand, subcommand arguments)."""
    configs: list[tuple[str, str]] = []
    dirs: list[str] = []
    j = 0
    while j < len(args) and args[j].startswith("-"):
        a = args[j]
        if a in ("-c", "--config-env") and j + 1 < len(args):
            key, _, value = args[j + 1].partition("=")
            configs.append((key.lower(), value))
            j += 2
            continue
        if a == "-C" and j + 1 < len(args):
            dirs.append(args[j + 1])
            j += 2
            continue
        if a in GIT_GLOBAL_VALUE:
            j += 2
            continue
        if a.startswith("--config-env="):
            key, _, value = a[len("--config-env="):].partition("=")
            configs.append((key.lower(), value))
        j += 1
    if j < len(args):
        return configs, dirs, args[j], args[j + 1:]
    return configs, dirs, "", []


def _configured_aliases(cwd: Path) -> dict[str, str]:
    key = str(cwd)
    if key not in _alias_cache:
        aliases: dict[str, str] = {}
        try:
            res = subprocess.run(["git", "config", "--get-regexp", r"^alias\."], cwd=cwd, capture_output=True,
                                 text=True, timeout=GIT_TIMEOUT)
            for line in res.stdout.splitlines():
                name, _, value = line.partition(" ")
                aliases[name[len("alias."):].lower()] = value
        except (OSError, subprocess.SubprocessError):
            pass
        _alias_cache[key] = aliases
    return _alias_cache[key]


def _git_top(cwd: Path) -> Path | None:
    try:
        res = subprocess.run(["git", "rev-parse", "--show-toplevel"], cwd=cwd, capture_output=True, text=True,
                             timeout=GIT_TIMEOUT)
    except (OSError, subprocess.SubprocessError):
        return None
    return Path(res.stdout.strip()) if res.returncode == 0 and res.stdout.strip() else None


def _shows_content(sub: str, args: list[str]) -> bool:
    opts = [a for a in itertools.takewhile(lambda x: x != "--", args) if a.startswith("-")]
    patch = any(_PATCH_FLAG.match(a) for a in opts)
    quiet = any(_NO_PATCH_FLAG.match(a) for a in opts)
    if sub in ("log", "whatchanged", "reflog", "diff-tree", "diff-index", "diff-files", "fast-export"):
        return patch or sub == "fast-export"
    if sub in ("show", "diff"):
        return patch or not quiet
    if sub == "stash":
        action = args[0] if args else ""
        return action in ("show", "list") and patch
    if sub == "cat-file":
        return not any(a in ("-t", "-s", "-e") or a.startswith("--batch-check") for a in opts)
    return True


# --------------------------------------------------------------------------
# Analysis
# --------------------------------------------------------------------------


def _unresolved(word: str) -> bool:
    return f"{MARK}S" in word or bool(_UNEXPANDED.search(word))


def _is_plugin_entry(word: str, base: Path, path_overridden: bool) -> bool:
    raw = _lit(word)
    try:
        if "/" in raw:
            return _abs(_expand_vars(raw, base), base).resolve() == PLUGIN_ENTRY.resolve()
        if path_overridden:
            return False
        found = shutil.which(raw)
        if found is None:
            # Claude Code puts the plugin's bin/ on the Bash tool's PATH, which
            # the hook's own PATH may lack.
            return PLUGIN_ENTRY.is_file()
        return Path(found).resolve() == PLUGIN_ENTRY.resolve()
    except (OSError, ValueError):
        return False


def _merge(result: Analysis, sub: Analysis) -> None:
    result.read_files += sub.read_files
    result.read_dirs += sub.read_dirs
    result.commits += sub.commits
    result.writes += sub.writes
    result.created += sub.created
    result.egress += sub.egress
    result.unresolved += sub.unresolved
    result.git_reads += sub.git_reads
    result.moves += sub.moves
    result.stages_changes |= sub.stages_changes
    result.disables_hooks |= sub.disables_hooks
    result.shows_staged |= sub.shows_staged


def _operands(args: list[str], value_opts: set[str]) -> tuple[list[str], str | None]:
    """(non-option words, -t/--target-directory value) for cp-like commands."""
    out: list[str] = []
    target: str | None = None
    i = 0
    end = False
    while i < len(args):
        a = args[i]
        if end or not a.startswith("-") or a == "-":
            out.append(a)
        elif a == "--":
            end = True
        elif a in ("-t", "--target-directory") and i + 1 < len(args):
            target = args[i + 1]
            i += 1
        elif a.startswith("--target-directory="):
            target = a.split("=", 1)[1]
        elif a in value_opts:
            i += 1
        i += 1
    return out, target


_GREP_VALUE_OPTS = {"-e", "-f", "-A", "-B", "-C", "-m", "-d", "-D", "--regexp", "--file", "--include", "--exclude",
                    "--exclude-dir", "--context", "--max-count", "--label", "-g", "--glob", "-t", "--type", "-T",
                    "--type-not", "-j", "--threads", "-M", "--max-columns", "-E", "--encoding", "--iglob", "--pre",
                    "--sort", "--sortr", "--max-depth", "--max-filesize", "--type-add", "--ignore-dir", "-r",
                    "--replace", "--colors", "--path-separator"}


def _search_operands(name: str, args: list[str]) -> list[str]:
    """Path operands of grep, rg, ag or ack: positional words after the pattern."""
    positional: list[str] = []
    has_pattern_opt = False
    skip = False
    end = False
    for a in args:
        if skip:
            skip = False
            continue
        if end or not a.startswith("-") or a == "-":
            positional.append(a)
            continue
        if a == "--":
            end = True
            continue
        if a in ("-e", "-f", "--regexp", "--file") or a.startswith(("--regexp=", "--file=")) \
                or re.fullmatch(r"-[A-Za-z]*[ef]\S*", a) and not a.startswith("--"):
            has_pattern_opt = True
        value_opts = _GREP_VALUE_OPTS - ({"-r"} if name in GREP_FAMILY else set())
        if a in value_opts and "=" not in a:
            skip = True
    return positional if has_pattern_opt else positional[1:]


def analyze(command: str, cwd: Path, depth: int = 0, feeds: bool = False, literal_only: bool = False) -> Analysis:
    """Analyse a command run in `cwd`.

    `feeds` marks a command whose output becomes another command's arguments
    (inside $(...) or piped to xargs), so a listing counts as a read.
    `literal_only` analyses text that is data rather than a command (a heredoc
    fed to cat, for example): literal paths in it count, unknown ones do not.
    """
    result = Analysis()
    if "core.hookspath" in command.lower():
        result.disables_hooks = True
    feeds = feeds or "xargs" in command
    top = _git_top(cwd) if "rev-parse --show-toplevel" in command else None
    prep = _prepare(command, top)
    bases = [cwd]
    oldpwd = cwd
    stack: list[Path] = []
    base_unknown = False
    variables: dict[str, list[str]] = {}
    path_overridden = False
    entry_shadowed = bool(re.search(r"(?:^|[\s;&|(])(?:function\s+)?phi-gate\s*\(\s*\)|alias\s+phi-gate=", command))
    reading_text: list[str] = []
    done_placeholders: set[str] = set()
    prev_seg: list[str] = []
    prev_name = ""

    def recurse(text: str, base: Path, *, as_feed: bool = False, literal: bool = False) -> None:
        if depth >= MAX_DEPTH:
            if not literal and not literal_only:
                result.unresolved.append("nesting too deep to follow")
            return
        _merge(result, analyze(text, base, depth + 1, feeds=as_feed or feeds, literal_only=literal or literal_only))

    def expand(word: str) -> list[str]:
        """The words `word` can become. An unknown variable stays in place,
        so the word reads as unresolved, and also expands to nothing, as
        an unset variable does."""
        word = _expand_vars(word, bases[-1], oldpwd)
        choices: list[list[str]] = []
        pos = 0
        for m in _VAR_REF.finditer(word):
            choices.append([word[pos:m.start()]])
            var = m.group(1) or m.group(4)
            values = variables.get(var)
            if values is None and var in os.environ and var not in ("PWD", "OLDPWD"):
                values = [os.environ[var]]
            op, default = m.group(2), m.group(3) or ""
            if values is None and op in (":-", "-", ":=", "="):
                values = [default]
            elif values is not None and op in (":+", "+"):
                values = [default]
            choices.append(values if values is not None else [m.group(0), ""])
            pos = m.end()
        if not choices:
            return [word]
        choices.append([word[pos:]])
        return ["".join(parts) for parts in itertools.islice(itertools.product(*choices), MAX_VALUES)]

    def place_holders(words: list[str], base: Path) -> None:
        for w in words:
            for m in _PLACEHOLDER.finditer(w):
                key = m.group(0)
                if key in done_placeholders:
                    continue
                done_placeholders.add(key)
                kind, k = m.group(1), int(m.group(2))
                if kind == "S" and k >= len(prep.subs) or kind == "P" and k >= len(prep.procs):
                    continue  # a placeholder from an enclosing command, recorded there
                if kind == "S":
                    recurse(prep.subs[k], base, as_feed=True)
                elif kind == "P":
                    recurse(prep.procs[k], base)

    for sep, seg in _segments(tokenize(prep.text)):
        piped = sep in ("|", "|&")
        base = bases[-1]
        place_holders(seg, base)

        if seg[0] in ("for", "select") and len(seg) >= 3 and seg[2] == "in":
            values: list[str] = []
            for w in seg[3:]:
                values += expand(w)
            variables[seg[1]] = [_lit(v) for v in values][:MAX_VALUES]
            prev_seg, prev_name = seg, seg[0]
            continue

        name, idx = _command_word(seg)
        via_xargs = any(os.path.basename(_lit(w)) == "xargs" for w in seg[:idx])
        args = seg[idx + 1:]
        for w in seg[:idx]:  # VAR=value prefixes and bare assignments
            m = _ASSIGN.match(w)
            if m:
                variables[m.group(1)] = [_lit(v) for v in expand(m.group(3))][:MAX_VALUES]
                path_overridden |= m.group(1) == "PATH"
        if name in ("export", "declare", "readonly", "local", "typeset"):
            for w in args:
                m = _ASSIGN.match(w)
                if m:
                    variables[m.group(1)] = [_lit(v) for v in expand(m.group(3))][:MAX_VALUES]
                    path_overridden |= m.group(1) == "PATH"

        # split redirections from words
        words: list[str] = []
        inputs: list[str] = []
        outputs: list[str] = []
        stdin_texts: list[str] = []
        i = idx + 1
        while i < len(seg):
            tok = seg[i]
            if tok == "<<<":
                if i + 1 < len(seg):
                    stdin_texts.append(_lit(seg[i + 1]))
                i += 2
                continue
            if re.fullmatch(r"\d*[<>]+&?|&>>?|>\|", tok):
                if i + 1 < len(seg):
                    target = seg[i + 1]
                    doc = _PLACEHOLDER.fullmatch(target)
                    if doc and doc.group(1) == "D":
                        stdin_texts.append(prep.docs[int(doc.group(2))])
                    elif "<" in tok:
                        inputs += expand(target)
                    elif not re.fullmatch(r"\d+|-", target) or "&" not in tok:
                        outputs += expand(target)
                i += 2
                continue
            if tok.isdigit() and i + 1 < len(seg) and re.fullmatch(r"[<>]+&?", seg[i + 1]):
                i += 1  # "2" in "2>/dev/null"
                continue
            words += expand(tok)
            i += 1

        # nested shells: bash -c "...", eval "...", bash <<EOF
        if name in SHELLS or name == "eval":
            inner = [a for a in args if " " in a or "\n" in a] or args[-1:]
            for script in inner:
                if f"{MARK}S" in script and not literal_only:
                    result.unresolved.append(f"{name} runs a script built when the command runs")
                recurse(_PLACEHOLDER.sub(" ", _lit(script)), base)
            for text in stdin_texts:
                recurse(text, base)
            if piped and prev_name in ("echo", "printf"):
                recurse(" ".join(_lit(w) for w in prev_seg[1:]), base)
        else:
            for text in stdin_texts:  # data for the command; literal paths in it still count
                recurse(text, base, literal=True)

        if name in ("cd", "pushd", "popd"):
            if name == "popd":
                if stack:
                    oldpwd = bases[-1]
                    bases.append(stack.pop())
                continue
            targets = [w for w in words if not w.startswith("-") or w == "-"]
            if not targets:
                target_word = str(Path.home()) if name == "cd" else ""
            else:
                target_word = targets[0]
            if not target_word or target_word.startswith("+"):
                base_unknown = True
                continue
            if target_word == "-":
                new = oldpwd
            elif _unresolved(target_word):
                base_unknown = True
                continue
            else:
                new = _abs(_lit(target_word), base)
            if name == "pushd":
                stack.append(base)
            oldpwd = base
            bases.append(new)
            continue

        reading = bool(name) and (name not in NON_READING or feeds)
        if name in KEYWORDS or name in ("done", "fi", "esac", "}"):
            reading = bool(inputs)
        egress = name in NETWORK
        if name == ENTRY_NAME:
            # The plugin's own read-only commands print locations or redacted
            # text, so the files they name are not exposed. --map writes the
            # original values out, so it counts as a read.
            action = _lit(args[0]) if args else ""
            trusted = not entry_shadowed and _is_plugin_entry(seg[idx], base, path_overridden)
            reading = not trusted or action not in PHI_GATE_SAFE or any(_lit(a).startswith("--map") for a in args)
        extra_bases: list[Path] = []
        read_words: list[str] | None = None  # when set, only these words are reads
        recursive_flag = any(
            a in ("--recursive", "--archive") or re.fullmatch(r"-[A-Za-z]*[rR][A-Za-z]*", a) for a in words
        )
        recursive = name in RECURSIVE_READERS or recursive_flag

        if name == "git":
            reading, shell_alias = _analyze_git(words, base, result, literal_only)
            if shell_alias:
                recurse(shell_alias, base)
            top_dir = _git_top(base)
            if top_dir is not None:
                extra_bases.append(top_dir)
            reading = reading or feeds
        if name == "find":
            reading = feeds or any(a in FIND_EXEC for a in words)
            starts = list(itertools.takewhile(lambda w: not w.startswith(("-", "(", "!")), words))
            if reading and not starts:
                result.read_dirs.append(base)
            if "-delete" in words:
                result.writes += _resolve(starts, bases, must_exist=False)

        if name in COPIERS:
            operands, target_dir = _operands(words, COPY_VALUE_OPTS.get(name, {"-S", "--suffix"}))
            if target_dir is not None:
                sources, dest = operands, target_dir
            elif len(operands) >= 2:
                sources, dest = operands[:-1], operands[-1]
            else:
                sources, dest = operands, None
            if dest is not None:
                result.created += _resolve([dest], bases, must_exist=False)
                if re.match(r"^[^/]*[^/\\]:", dest) or dest.startswith(("rsync://", "sftp://")):
                    egress = True
            recursive = recursive or name == "ln" or any(re.fullmatch(r"-[A-Za-z]*a[A-Za-z]*", w) for w in words)
            if name == "mv":
                if dest is not None:
                    result.moves.append(Move(_resolve(sources, bases), _abs(_lit(dest), base)))
                read_words = []
                reading = False
            else:
                read_words = sources
                reading = True
        if name in MODIFIERS or (name == "sed" and any(w.startswith("-i") or w == "--in-place" for w in words)):
            result.created += _resolve([w for w in words if not w.startswith("-")], bases, must_exist=False)
        if name == "dd":
            result.created += _resolve([w[3:] for w in words if w.startswith("of=")], bases, must_exist=False)
        result.created += _resolve(outputs, bases, must_exist=False)

        if any(re.match(r"^/dev/(?:tcp|udp)/", _lit(o)) for o in outputs + inputs):
            egress = True
        if any(_DEV_STREAM.match(_lit(w)) for w in words + outputs):
            reading = True  # cp file /dev/stdout prints it

        # interpreters: inline scripts and scripts on stdin
        lang = _language(name)
        scripts: list[str] = []
        if lang is not None:
            inline, from_stdin = _inline_scripts(lang, [_lit(w) for w in words])
            scripts += inline
            if from_stdin:
                scripts += stdin_texts
                if piped and prev_name in ("echo", "printf"):
                    scripts.append(" ".join(_lit(w) for w in prev_seg[1:]))
        for script in scripts:
            computed, network = script_access(script, lang or "other")
            if computed and not literal_only:
                result.unresolved.append(f"{name} script builds a file path at run time")
            if network:
                egress = True
            reading_text.append(script)
        if egress:
            result.egress.append(name or "redirection")

        candidates: list[str] = []
        source_words = words if read_words is None else read_words
        for w in source_words:
            if w.startswith("-") and w != "-":
                if "=" in w:
                    candidates.append(w.split("=", 1)[1])
                continue
            candidates.append(w.split("=", 1)[1] if _ASSIGN.match(w) else w)
            if name in ("curl", "wget", "http", "https", "xh") and "@" in w:
                candidates.append(w.split("@", 1)[1])
            if " " in w or "(" in w or "'" in w or '"' in w:  # inline script: look for paths inside
                candidates += [m.group(0) for m in _EMBEDDED_PATH.finditer(_lit(w)[:MAX_EMBEDDED_SCAN])]
        if name in ("curl", "wget"):
            candidates += [w.split("@", 1)[1] for w in words if w.startswith("-") and "@" in w]

        search = bases + extra_bases
        literal_candidates = [_lit(c) for c in candidates if not _unresolved(c)]
        literal_inputs = [_lit(c) for c in inputs if not _unresolved(c)]
        resolved_reads = _resolve(literal_candidates + literal_inputs, search)
        if name in WRITE_WORDS:
            result.writes += _resolve([_lit(c) for c in candidates], bases, must_exist=False)
        result.writes += _resolve([_lit(o) for o in outputs], bases, must_exist=False)

        if via_xargs and (reading or egress) and not literal_only:
            result.unresolved.append(f"xargs {name}: arguments read from standard input")
        if (reading or egress) and not literal_only and name != "git":
            unknown = [c for c in candidates + inputs if _unresolved(c)]
            if unknown:
                result.unresolved.append(f"{name}: {_lit(unknown[0])[:80]}")
            elif base_unknown and any(not os.path.isabs(_lit(c)) for c in candidates + inputs if c):
                result.unresolved.append(f"{name} after a change to an unknown directory")
        elif inputs and not literal_only and any(_unresolved(c) for c in inputs):
            result.unresolved.append(f"{name}: input {_lit(inputs[0])[:80]}")

        if reading and (name in GREP_FAMILY and recursive_flag or name in ALWAYS_RECURSIVE):
            # rg and similar search standard input when it is a pipe or a file; --files lists names only
            no_tree = name in ALWAYS_RECURSIVE and bool(piped or inputs or stdin_texts or "--files" in words)
            if not _search_operands(name, [_lit(w) for w in words]) and not no_tree:
                result.read_dirs.append(base)

        input_paths = {os.path.normpath(str(_abs(_lit(x), base))) for x in inputs}
        if reading:
            reading_text.append(" ".join(_lit(w) for w in (seg if read_words is None else read_words)))
        for p in resolved_reads:
            try:
                if p.is_file():
                    if reading or os.path.normpath(str(p)) in input_paths:
                        result.read_files.append(p)
                elif p.is_dir() and reading and recursive:
                    result.read_dirs.append(p)
            except OSError:
                continue
        prev_seg, prev_name = seg, name

    # placeholders that no segment reached (inside heredoc bodies, for example)
    leftovers = [f"{MARK}S{k}{MARK}" for k in range(len(prep.subs))] + \
        [f"{MARK}P{k}{MARK}" for k in range(len(prep.procs))]
    place_holders(leftovers, bases[-1])

    # Paths anywhere in the text of reading segments: heredoc bodies, inline
    # scripts, arguments the per-word analysis could not attribute.
    if reading_text:
        joined = "\n".join(reading_text)[:MAX_EMBEDDED_SCAN]
        embedded = [m.group(0) for m in _EMBEDDED_PATH.finditer(joined)]
        for p in _resolve(embedded, bases):
            try:
                if p.is_file():
                    result.read_files.append(p)
            except OSError:
                continue

    result.read_files = _dedupe(result.read_files)
    result.read_dirs = _dedupe(result.read_dirs)
    result.writes += result.created
    return result


def _language(name: str) -> str | None:
    m = _INTERPRETER.match(name)
    if not m:
        return None
    return next(lang for lang, g in zip(_LANGS, m.groups(), strict=True) if g is not None)


def _analyze_git(words: list[str], base: Path, result: Analysis, literal_only: bool) -> tuple[bool, str]:
    """Record commits, history reads and hook changes for one git invocation.
    Returns (whether the generic file-read analysis applies, a shell alias
    command to analyse)."""
    lits = [_lit(w) for w in words]
    for w in lits:
        if "core.hookspath" in w.lower():
            result.disables_hooks = True
    configs, dirs, sub, sub_args = _parse_git(lits)
    git_base = base
    for d in dirs:
        git_base = _abs(d, git_base)
    inline = {k[len("alias."):]: v for k, v in configs if k.startswith("alias.")}
    shell_alias = ""
    for _ in range(5):
        if not sub or sub in GIT_BUILTINS:
            break
        value = inline.get(sub.lower())
        if value is None:
            value = _configured_aliases(git_base).get(sub.lower())
        if value is None:
            break
        if "core.hookspath" in value.lower():
            result.disables_hooks = True
        if value.startswith("!"):
            shell_alias = value[1:] + " " + " ".join(shlex.quote(a) for a in sub_args)
            return False, shell_alias
        try:
            parts = shlex.split(value)
        except ValueError:
            parts = value.split()
        if not parts:
            break
        if parts[0].startswith("-"):
            more, more_dirs, sub, rest = _parse_git(parts)
            configs += more
            for d in more_dirs:
                git_base = _abs(d, git_base)
            sub_args = rest + sub_args
        else:
            sub, sub_args = parts[0], parts[1:] + sub_args

    if sub in COMMIT_LIKE:
        if sub == "commit":
            bypass, include_all = commit_flags(sub_args)
        else:
            bypass, include_all = _long_no_verify(sub_args), False
        result.commits.append(Commit(sub_args, bypass, include_all, sub))
    if sub == "add":
        result.stages_changes = True
    if sub == "diff" and ("--cached" in sub_args or "--staged" in sub_args):
        result.shows_staged = True
    if sub == "clean" and any(a.startswith("-") and not a.startswith("--") and ("x" in a or "X" in a)
                              for a in sub_args):
        result.writes.append(git_base / ".phi-gate")
    if sub in HISTORY_SUBS and not literal_only and _shows_content(sub, sub_args):
        unresolved = any(_unresolved(w) for w in words)
        result.git_reads.append(GitRead(sub, list(sub_args), git_base, unresolved))
    return sub not in GIT_NON_READING, shell_alias


_DEV_STREAM = re.compile(r"^/(?:dev/(?:std(?:out|err)|fd/|tty)|proc/self/fd/)")
FIND_EXEC = {"-exec", "-execdir", "-ok", "-okdir"}
PHI_GATE_SAFE = {"scan", "redact", "status", "explain", "--version", "--help", "-h"}


def _abs(word: str, base: Path) -> Path:
    p = Path(word)
    return p if p.is_absolute() else base / p


def _resolve(words: list[str], bases: list[Path], must_exist: bool = True) -> list[Path]:
    out: list[Path] = []
    for raw in words:
        if not raw or MARK in raw:
            continue
        for base in bases:
            word = _expand_vars(raw, base)
            for w in _expand_braces(word):
                if any(ch in w for ch in "*?["):
                    pattern = w if os.path.isabs(w) else str(base / w)
                    try:
                        out += [Path(m) for m in glob.glob(pattern)[:500]]
                    except (OSError, ValueError):
                        pass
                    if not must_exist:
                        out.append(_abs(w, base))
                else:
                    try:
                        p = _abs(w, base)
                        if not must_exist or p.exists():
                            out.append(p)
                    except (OSError, ValueError):
                        continue
    return out


def _dedupe(paths: list[Path]) -> list[Path]:
    seen: set[str] = set()
    out = []
    for p in paths:
        key = os.path.normpath(str(p))
        if key not in seen:
            seen.add(key)
            out.append(Path(key))
    return out


# --------------------------------------------------------------------------
# What a git history read prints
# --------------------------------------------------------------------------


@dataclass
class Blob:
    """A file a git command would print: an object in the repository (`sha`)
    or the working-tree file (`sha` is None). `path` is relative to the top
    of the working tree."""

    path: str
    sha: str | None


class Undetermined(Exception):
    """The set of files a git command would print could not be determined."""


ZERO_SHA = re.compile(r"^0+$")
_KEEP_LOG_OPTS = re.compile(
    r"^(?:-\d+|--max-count=\d+|--skip=\d+|--(?:since|after|until|before|author|committer|grep|glob|"
    r"branches|tags|remotes)(?:=.*)?|--all|-g|--walk-reflogs|--first-parent|--no-merges|--merges|--follow|"
    r"-[SG].+|--cached|--staged|--merge-base|-R|--root)$"
)
_LOG_VALUE_OPTS = {"-n", "--max-count", "--skip", "--since", "--after", "--until", "--before", "--author",
                   "--committer", "--grep", "-S", "-G", "-L", "--format", "--pretty", "--date", "-O", "--stat-width",
                   "--diff-filter", "--relative", "-U", "--unified", "--encoding"}


def _git(args: list[str], cwd: Path, input_text: str | None = None) -> str:
    try:
        res = subprocess.run(["git", "-c", "core.quotepath=off", *args], cwd=cwd, capture_output=True, text=True,
                             input=input_text, timeout=GIT_TIMEOUT, errors="surrogateescape")
    except subprocess.TimeoutExpired as exc:
        raise Undetermined("git took too long to list the files") from exc
    except (OSError, subprocess.SubprocessError) as exc:
        raise Undetermined(f"git could not run ({exc})") from exc
    if res.returncode != 0:
        raise Undetermined(f"git could not resolve the arguments ({res.stderr.strip()[:120]})")
    return res.stdout


def _split_paths(args: list[str]) -> tuple[list[str], list[str]]:
    if "--" in args:
        k = args.index("--")
        return args[:k], args[k + 1:]
    return args, []


def _log_args(args: list[str]) -> tuple[list[str], list[str], list[str]]:
    """(options kept, revision words, paths) from log-like arguments."""
    before, paths = _split_paths(args)
    opts: list[str] = []
    words: list[str] = []
    i = 0
    while i < len(before):
        a = before[i]
        if a.startswith("-") and a != "-":
            if a == "-n" and i + 1 < len(before):
                opts += [a, before[i + 1]]
                i += 2
                continue
            if a == "-L" and i + 1 < len(before) or a.startswith("-L") and len(a) > 2:
                spec = before[i + 1] if a == "-L" else a[2:]
                paths.append(spec.rsplit(":", 1)[-1])
                i += 2 if a == "-L" else 1
                continue
            if a in _LOG_VALUE_OPTS and i + 1 < len(before):
                if _KEEP_LOG_OPTS.match(f"{a}={before[i + 1]}"):
                    opts.append(f"{a}={before[i + 1]}")
                i += 2
                continue
            if _KEEP_LOG_OPTS.match(a):
                opts.append(a)
            i += 1
            continue
        words.append(a)
        i += 1
    return opts, words, paths


def _raw_blobs(text: str) -> list[Blob]:
    out: list[Blob] = []
    for line in text.splitlines():
        if not line.startswith(":") or "\t" not in line:
            continue
        meta, _, names = line.partition("\t")
        fields = meta.lstrip(":").split()
        if len(fields) < 5:
            continue
        old_mode, new_mode, old_sha, new_sha = fields[:4]
        parts = names.split("\t")
        old_path, new_path = parts[0], parts[-1]
        if old_mode != "160000" and not ZERO_SHA.match(old_sha):
            out.append(Blob(old_path, old_sha))
        if new_mode == "160000":
            continue
        if ZERO_SHA.match(new_sha):
            if new_mode != "000000":
                out.append(Blob(new_path, None))  # working-tree side of a diff
        else:
            out.append(Blob(new_path, new_sha))
    return out


def _tree_blobs(tree: str, paths: list[str], cwd: Path) -> list[Blob]:
    out: list[Blob] = []
    for line in _git(["ls-tree", "-r", "--full-name", tree, "--", *paths], cwd).splitlines():
        meta, _, path = line.partition("\t")
        fields = meta.split()
        if len(fields) >= 3 and fields[1] == "blob":
            out.append(Blob(path, fields[2]))
    return out


def _object_type(obj: str, cwd: Path) -> str:
    return _git(["cat-file", "-t", obj], cwd).strip()


def _log_blobs(opts: list[str], words: list[str], paths: list[str], cwd: Path, extra: list[str] | None = None) -> list[Blob]:
    args = ["log", "--format=", "--raw", "--no-abbrev", "-r", "-m", *(extra or []), *opts, *words]
    if paths:
        args += ["--", *paths]
    return _raw_blobs(_git(args, cwd))


def _object_blobs(obj: str, paths: list[str], cwd: Path) -> list[Blob]:
    if ".." in obj or obj.startswith("^"):
        return _log_blobs([], [obj], paths, cwd)
    if ":" in obj and not obj.startswith(":/"):
        sha = _git(["rev-parse", "--verify", "--quiet", obj], cwd).strip()
        kind = _object_type(sha, cwd)
        if kind == "tree":
            return _tree_blobs(sha, [], cwd)
        return [Blob(obj.split(":", 1)[1].removeprefix("./") or obj, sha)] if kind == "blob" else []
    kind = _object_type(obj + "^{}", cwd)
    if kind == "commit":
        return _log_blobs([], ["-1", obj], paths, cwd)
    if kind == "tree":
        return _tree_blobs(obj + "^{}", paths, cwd)
    if kind == "blob":
        return [Blob(obj, _git(["rev-parse", obj], cwd).strip())]
    return []


def _stash_blobs(rev: str, cwd: Path) -> list[Blob]:
    blobs = _raw_blobs(_git(["diff", "--raw", "--no-abbrev", f"{rev}^1", rev], cwd))
    try:
        blobs += _tree_blobs(f"{rev}^3", [], cwd)
    except Undetermined:
        pass  # the stash has no untracked files
    return blobs


def _positional(args: list[str], value_opts: set[str]) -> list[str]:
    out: list[str] = []
    skip = False
    for a in args:
        if skip:
            skip = False
            continue
        if a.startswith("-") and a != "-":
            if a in value_opts:
                skip = True
            continue
        out.append(a)
    return out


def history_blobs(read: GitRead) -> list[Blob]:
    """The files `read` would print. Raises Undetermined when that cannot be
    worked out without running the command."""
    if read.unresolved:
        raise Undetermined("its arguments are computed when the command runs")
    sub, args, cwd = read.sub, read.args, read.cwd
    if sub == "bundle":
        if args[:1] != ["create"]:
            return []
        opts, words, paths = _log_args(args[2:])
        return _log_blobs(opts, words, paths, cwd)
    if sub in ("log", "whatchanged", "fast-export", "range-diff"):
        opts, words, paths = _log_args(args)
        return _log_blobs(opts, words, paths, cwd)
    if sub == "reflog":
        rest = args[1:] if args[:1] == ["show"] else args
        opts, words, paths = _log_args(rest)
        return _log_blobs(opts, words, paths, cwd, extra=["-g"])
    if sub == "format-patch":
        opts, words, paths = _log_args(args)
        words = [w if ".." in w else f"{w}..HEAD" for w in words]
        if not words and any(re.fullmatch(r"-\d+", o) or o == "-n" for o in opts):
            words = ["HEAD"]
        return _log_blobs(opts, words, paths, cwd)
    if sub == "show":
        before, paths = _split_paths(args)
        objs = _positional(before, {"--format", "--pretty", "-O"}) or ["HEAD"]
        out: list[Blob] = []
        for obj in objs:
            out += _object_blobs(obj, paths, cwd)
        return out
    if sub in ("diff", "diff-tree", "diff-index", "diff-files"):
        opts, words, paths = _log_args(args)
        if "--no-index" in args:
            return []
        keep = [o for o in opts if o in ("--cached", "--staged", "--merge-base", "-R")]
        cmd = [sub, "--raw", "--no-abbrev", *(["-r"] if sub == "diff-tree" else []), *keep, *words]
        if paths:
            cmd += ["--", *paths]
        return _raw_blobs(_git(cmd, cwd))
    if sub == "stash":
        action, rest = (args[0], args[1:]) if args else ("show", [])
        if action == "list":
            refs = _git(["stash", "list", "--format=%gd"], cwd).split()
            out = []
            for ref in refs[:50]:
                out += _stash_blobs(ref, cwd)
            return out
        revs = _positional(rest, set())
        rev = revs[0] if revs else "stash@{0}"
        if rev.isdigit():
            rev = f"stash@{{{rev}}}"
        return _stash_blobs(rev, cwd)
    if sub == "grep":
        return _grep_blobs(args, cwd)
    if sub == "archive":
        before, paths = _split_paths(args)
        if any(a == "--remote" or a.startswith("--remote=") for a in before):
            return []
        pos = _positional(before, {"--format", "-o", "--output", "--prefix", "--exec", "--add-file", "--mtime"})
        if not pos:
            raise Undetermined("no tree was named")
        out = _tree_blobs(pos[0], pos[1:] + paths, cwd)
        out += [Blob(a.split("=", 1)[1], None) for a in before if a.startswith("--add-file=")]
        return out
    if sub == "cat-file":
        if any(a.startswith("--batch") for a in args):
            raise Undetermined("it reads object names from standard input")
        pos = _positional(args, {"--path", "--filters"})
        if not pos:
            return []
        obj = pos[-1]
        sha = _git(["rev-parse", "--verify", "--quiet", obj], cwd).strip()
        if _object_type(sha, cwd) != "blob":
            return []
        return [Blob(obj.split(":", 1)[1] if ":" in obj else obj, sha)]
    if sub in ("blame", "annotate"):
        before, paths = _split_paths(args)
        pos = _positional(before, {"-L", "-S", "--contents", "--since", "--ignore-rev", "--ignore-revs-file"})
        if not paths and pos:
            paths = [pos.pop()]
        if not pos or not paths:
            return []  # blame of the working-tree file, which the file analysis scans
        rev = pos[0]
        sha = _git(["rev-parse", "--verify", "--quiet", f"{rev}:./{paths[0]}"], cwd).strip()
        return [Blob(paths[0], sha)]
    return []


def _grep_blobs(args: list[str], cwd: Path) -> list[Blob]:
    before, paths = _split_paths(args)
    value_opts = {"-e", "-f", "-A", "-B", "-C", "-m", "--max-count", "--max-depth", "--threads", "-O",
                  "--open-files-in-pager", "--context", "--before-context", "--after-context"}
    pos = _positional(before, value_opts)
    if not any(a in ("-e", "-f") or re.fullmatch(r"-[A-Za-z]*[ef]", a) for a in before):
        pos = pos[1:]
    revs: list[str] = []
    for w in pos:
        try:
            _git(["rev-parse", "--verify", "--quiet", f"{w}^{{tree}}"], cwd)
            revs.append(w)
        except Undetermined:
            paths.append(w)
    if revs:
        out: list[Blob] = []
        for rev in revs:
            out += _tree_blobs(rev, paths, cwd)
        return out
    if "--cached" in before:
        out = []
        for line in _git(["ls-files", "-s", "--full-name", "--", *paths], cwd).splitlines():
            meta, _, path = line.partition("\t")
            fields = meta.split()
            if len(fields) >= 2:
                out.append(Blob(path, fields[1]))
        return out
    listing = ["ls-files", "--full-name"]
    if "--untracked" in before or "--no-index" in before:
        listing += ["--cached", "--others", "--exclude-standard"]
    return [Blob(p, None) for p in _git([*listing, "--", *paths], cwd).splitlines()]

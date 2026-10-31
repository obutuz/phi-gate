# HIPAA Safe Harbor identifiers

Under the Safe Harbor de-identification method (45 CFR 164.514(b)(2)), data is
de-identified when these 18 identifiers of the individual, and of relatives,
employers or household members, are removed and the entity has no actual
knowledge that the rest could identify the person.

| # | Identifier | phi-gate detection |
|---|------------|--------------------|
| A | Names | Labelled names (`Patient Name:`, `patientName`), X12 `NM1*QC/IL`, HL7 `PID`, FHIR `Patient`, name columns in tables |
| B | Geographic units smaller than a state (street, city, county, ZIP; first 3 ZIP digits allowed for areas over 20,000 people) | Street addresses, `City, ST 12345` |
| C | All date elements except year tied to the individual (birth, admission, discharge, death); ages over 89 | Labelled DOB, admission, discharge, service and death dates; X12 `DMG*D8` |
| D | Telephone numbers | US formats (toll-free and 555-01xx excluded) |
| E | Fax numbers | Same as phone |
| F | Email addresses | Yes (example/test domains excluded) |
| G | Social Security numbers | Dashed in issued ranges; labelled 9-digit |
| H | Medical record numbers | Labelled MRN, patient ID, chart number |
| I | Health plan beneficiary numbers | Medicare MBI format; labelled member, subscriber, Medicaid and Medicare IDs |
| J | Account numbers | Labelled account numbers; Luhn-valid payment cards |
| K | Certificate and license numbers | Not detected |
| L | Vehicle identifiers, license plates | Not detected |
| M | Device identifiers and serial numbers | Not detected |
| N | Web URLs | Not detected (too common in code) |
| O | IP addresses | Public IPv4, informational only |
| P | Biometric identifiers | Not detected |
| Q | Full-face photographs | Not inspected (images are opaque to phi-gate) |
| R | Any other unique identifying number or code | Partly, through labelled-ID detectors |

Provider identifiers (NPI, DEA) identify clinicians, not patients, so phi-gate
reports them as informational and never blocks on them alone.

The other HIPAA de-identification method, Expert Determination
(164.514(b)(1)), relies on a qualified statistician's documented analysis. No
pattern scanner can replace it.

## What "PHI" means for a scanner

Identifiers become PHI when they are tied to health information held by a covered
entity or business associate. phi-gate encodes that as a policy:

- Identifiers that only make sense in a health context (SSN, MRN, member ID, DOB,
  patient-labelled names, EDI/HL7/FHIR patient segments, patient tables) block on
  their own.
- Ordinary contact details (a name and an email) only warn, unless a clinical fact
  (diagnosis code, date of service) sits next to them.

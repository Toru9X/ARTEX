---
name: export-report-injection
description: "Invoke this skill when the application produces or serves exported files or reports: CSV/XLSX/PDF/HTML exports, export jobs with download links or passwords, evidence file storage (S3 or presigned URLs), report generation. Covers formula injection into cells, export-job IDOR, download link and password handling, content-type and disposition, storage keys, and what can be proven with read-only requests."
---

# Exports, reports and evidence files

## 1. Read the code first
Find the export pipeline (`exportjob`, `xlsx`, `csv`, `report`, `evidencestore`, `presign`, `s3`) and answer from source before touching the live system:
- Cell sanitisation: is every user-controlled value passed through a sanitiser that neutralises a leading `=`, `+`, `-`, `@`, tab and CR (formula injection)? Look for a helper such as `SanitizeCell` and for cells that BYPASS it: numeric-looking strings, hyperlinks, header cells, sheet names, document properties.
- Authorization of jobs: is a job looked up by id alone, or by id AND the caller? A `FindForUser`-style lookup is the right pattern; a bare `GetByID` is BOLA.
- Download: signed or presigned URL lifetime, whether the URL is bound to the caller, `Content-Disposition: attachment`, content-type derived from the bytes or from the client, `nosniff`.
- Passwords on archives or xlsx: length and randomness (crypto/rand?), and whether the password appears in a response that should not be cached, or in logs.
- Storage keys: are object keys built from user input (path traversal, key collision, overwriting another tenant's object), or bound to the owning object id?
- Uploads: size cap, magic-byte versus extension check, filename sanitisation (`filepath.Base`), SVG or HTML allowed or not, ZIP/XLSX handled server-side (zip-slip, XXE inside the XLSX XML).

## 2. Live-safe checks (read only)
- List and get export jobs and reports with two scopes you legitimately hold (for example two `x-org-id` values). A job, report or evidence id taken from scope A and requested under scope B must be 404 or 403. Same for endpoints that issue presigned URLs.
- Response headers on download endpoints: `Cache-Control: no-store`, `Content-Disposition`, `X-Content-Type-Options`.
- Error behaviour on malformed ids (`not-a-uuid`): a raw database error in the body (`pq: invalid input syntax`) is an information-disclosure finding of Low severity, not SQL injection when the value is a bound parameter. Control: a valid UUID returns 200.

## 3. Needs a write (do not do it live)
Creating an export that contains `=cmd|...` or `=HYPERLINK(...)` values to see whether they survive sanitisation needs data creation. If creating records is not authorised, record "formula injection unverified: needs a record with a hostile cell value", with the file:line of the sanitiser and the cells that skip it.

## 4. Evidence standard
Formula injection counts only if a hostile value is shown to reach a spreadsheet cell unsanitised (inspect the produced file, not just the code). A sanitiser check in source that you cannot trigger is a source-only observation.

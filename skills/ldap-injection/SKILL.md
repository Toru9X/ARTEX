---
name: ldap-injection
description: "LDAP and LDAP-filter injection: authentication bypass with a wildcard or always-true filter, blind attribute enumeration character by character, and directory data extraction through a search box backed by Active Directory or another LDAP store. Use when login, user search, group lookup, address book or any corporate-directory feature sits in front of AD/LDAP, or when input containing ( ) * | & or \ changes the result set or produces a filter or protocol error."
---

# LDAP Injection

A login form backed by Active Directory builds a filter string. If your input is concatenated into it, the same mistakes as SQL injection apply, with a different grammar.

## Crown Jewel Targets

- **Authentication bypass** — `*)(uid=*))(|(uid=*` or a trailing `*` as the password against a bind that does not re-verify
- **Blind attribute extraction** — recover password hashes, email, group membership one character at a time
- **Privilege discovery** — enumerate members of `Domain Admins` through a user-search box
- **Filter scope escape** — widen a search from one OU to the whole directory

## Attack Surface Signals

- Corporate SSO/intranet login, "search for a colleague", group pickers, address books
- An error containing `LDAP`, `javax.naming`, `ldap_search`, `Bad search filter`, `LDAPException`, or an OID like `1.3.6.1.4.1.1466`
- Input with `(` or `)` producing a 500 while other punctuation does not
- A `*` in a search box returning *everything* — the filter is concatenated and unescaped

## Method

1. **Detect the grammar.** Send `*` alone: a full result set means the wildcard reached the filter. Send `(` alone: a filter-syntax error means raw concatenation.
2. **Confirm with a logic pair.** `admin)(|(uid=*` versus `admin)(&(uid=nonexistent` — a true/false difference in the response proves control of the filter, the same way `' OR 1=1` does for SQL.
3. **Bypass the bind.** On a login form try `*)(uid=*))(|(uid=*` in the username and anything in the password; also try username `admin*` with an empty password where anonymous bind is allowed.
4. **Extract blind.** Use a prefix oracle: `admin)(userPassword=a*` and walk the alphabet, reading the true/false signal from step 2. Script it; do not do it by hand.
5. **Enumerate attributes** the filter will return — `cn`, `mail`, `memberOf`, `userPassword`, `sAMAccountName`.

Escape rules for your own payloads: `\28` for `(`, `\29` for `)`, `\2a` for `*`, `\5c` for `\`.

## Evidence That Survives Triage

Show the authenticated session you obtained without valid credentials, or the directory data you extracted that your account could not otherwise read, with the exact request. A 500 containing an LDAP error is **information disclosure**, not LDAP injection — report it as that instead if you cannot reach data.

## Common False Positives

- A search box that legitimately supports `*` as a documented wildcard
- A 500 on `(` caused by a generic input validator, not the LDAP layer
- A result-count change caused by normal relevance ranking

See [[auth-bypass-testing]], [[sql-injection-testing]], [[information-disclosure]].

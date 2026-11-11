---
name: graphql-testing
description: "GraphQL testing — introspection schema dump, authorization gaps on crafted queries, SQLi through variables, alias batching to defeat rate limits, and CSRF via GET-based mutations. Use when a /graphql, /api/graphql, Hasura, or Apollo endpoint is reachable — schema disclosure alone stays informational until data access is proven."
---

# GraphQL Introspection + Data Extraction

## Crown Jewel Targets

- **Unauthorized data access** — introspection reveals User/Account/Payment types, crafted queries extract PII without proper authorization
- **GraphQL SQLi** — variables passed directly to SQL backend (e.g., `{"id":"1' OR '1'='1"}`) for database extraction
- **Alias-based rate limit bypass** — single request with 100+ aliased login mutations counting as one rate limit check
- **Schema reconstruction via suggestions** — "Did you mean...?" error messages leak field names even when introspection is disabled
- **CSRF via GET-based GraphQL** — GET requests and `x-www-form-urlencoded` POST are CSRF-forgeable for state-changing mutations
- **Hasura/Apollo admin access** — default admin secret or misconfigured role-based access enabling full CRUD

## Attack Surface Signals

- `/graphql`, `/api/graphql`, `/v1/graphql` endpoints responding to POST
- `query{__typename}` returning `{"data":{"__typename":"query"}}` (universal fingerprint)
- GraphQL error messages with field suggestions ("Did you mean...?")
- Apollo, Hasura, NestJS GraphQL indicators in response headers/errors
- GraphQL Playground or GraphiQL interface exposed publicly
- Content-Type `application/graphql` or `application/json` with query field

## Detection
```bash
# Test introspection
curl -X POST TARGET/graphql -H "Content-Type: application/json" \
  -d '{"query":"{__schema{types{name fields{name}}}}"}'

# Also try /api/graphql
curl -X POST TARGET/api/graphql -H "Content-Type: application/json" \
  -d '{"query":"{__schema{types{name fields{name}}}}"}'
```

## Exploitation Steps
1. Introspection → full schema
2. Identify sensitive types (User, Account, Payment, etc.)
3. Craft queries to access data
4. Test for authorization: can anonymous user access user data?
5. Test for SQLi in variables: `{"id":"1' OR '1'='1"}`

## Severity Guide
| Finding | Severity |
|---------|----------|
| Introspection alone (no data access) | Low/Informational |
| Introspection + schema reveals sensitive types | Medium |
| Introspection + unauthorized data access | High |
| GraphQL SQLi | Exceptional |

## Historical Results
- target-corp: SQLi in GraphQL variables → Exceptional
- WaPo: Introspection on brand + talk subdomains
- Pokemon: Salesforce GraphQL (blocked by permissions)

## Note
GraphQL introspection ALONE is often not reportable. Must demonstrate data access or injection.

## PortSwigger Academy — Advanced Techniques

- **Introspection newline bypass**: `{"query":"query{__schema\n{queryType{name}}}"}` — bypasses regex blocks
- **HTTP method bypass**: GET with URL-encoded query when POST blocks introspection
- **Content-type bypass**: `x-www-form-urlencoded` instead of `application/json`
- **Apollo suggestions exploitation**: Error messages leak field names ("Did you mean...?") — use `clairvoyance` tool for full schema reconstruction
- **Rate limit bypass via aliases**: Single request with aliased operations: `{a1:login(pw:"p1"){token} a2:login(pw:"p2"){token}}`
- **Universal fingerprint**: `query{__typename}` returns `{"data":{"__typename":"query"}}`
- **CSRF via GET-based GraphQL**: GET and `x-www-form-urlencoded` POST are CSRF-forgeable

---

## Exploiting unsanitized arguments and mapping the schema

**Unsanitized arguments are the highest-yield GraphQL bug and the one most often skipped** in favour of dumping introspection. Every argument is a parameter that reaches a resolver, and resolvers frequently pass values straight into a database call, a file read, or an internal HTTP request. Test each argument the way you would any other injectable parameter:

- Object IDs → IDOR/BOLA. Request neighbouring IDs directly; GraphQL authorization is enforced per-resolver and one resolver frequently forgets.
- String arguments → SQLi/NoSQLi, path traversal, SSRF, depending on what the resolver does with them.
- Arguments accepted in **variables** rather than inline — the same injection often behaves differently there, and WAFs inspect the two paths inconsistently.

**Visualizing the schema.** A raw introspection JSON is unusable at scale; feed it to **GraphQL Voyager** to get a navigable graph of types and relationships. This is how you spot the mutation nobody documented and the type that links user records to payment records. `clairvoyance` reconstructs a schema from field **suggestions** ("Did you mean ...?") when introspection is disabled — suggestions leak the schema even on hardened endpoints.

Remember the project rule: a schema dump alone stays informational. The finding is the data or the action the schema led you to.

## Operator Notes (Battle-Tested)

- **Introspection ALONE is often NOT reportable** — MEMORY: schema disclosure = informational. Must demonstrate unauthorized data access or injection to get a bounty
- **Use `clairvoyance` tool when introspection is disabled** — "Did you mean...?" error messages leak field names. Clairvoyance automates full schema reconstruction from suggestions
- **Newline bypass for introspection block** — `{"query":"query{__schema\n{queryType{name}}}"}` bypasses regex-based introspection blocking
- **Try GET with URL-encoded query** — some implementations block POST introspection but allow GET requests with query parameter
- **GraphQL SQLi in variables is the Critical escalation** — `{"id":"1' OR '1'='1"}` in variable values. target-corp got Exceptional severity for this
- **Alias batching for rate limit bypass** — `{a1:login(pw:"p1"){token} a2:login(pw:"p2"){token}}` — 100+ aliases per request for credential stuffing
- **CSRF via GET-based GraphQL** — GET requests and `x-www-form-urlencoded` POST are CSRF-forgeable for state-changing mutations

## Related Skills & Chains

| Situation | Pattern / Skill |
|-----------|----------------|
| Rate limit bypass via GraphQL aliases | `rate-limit-bypass` |
| SQLi in GraphQL variables | `sql-injection-testing` → `references/nosqli-techniques.md` (or standard SQLi) |
| API testing methodology | `api-security-testing` |
| Access control on GraphQL resolvers | `access-control-testing` |
| CORS on GraphQL endpoint | `cors-testing` |
| CSRF on GraphQL mutations | `csrf-testing` |
| Chain escalation matrix | `auto-chain-discovery` |

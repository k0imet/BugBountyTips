
# HackerOne CWE + CVE Discovery Manual Bug Bounty Cheatsheet

**Generated:** 2026-05-05  
**Audience:** authorized bug bounty hunters, application security testers, junior-to-intermediate pentesters, and people who prefer manual validation over scanner-only hunting.  
**Scope:** web apps, APIs, mobile-backed APIs, SaaS apps, cloud-facing services, documentation/API surfaces, and public assets that are explicitly in scope.  
**Boundary:** this guide is for authorized testing only. Do not test assets that are not in scope. Do not attempt denial-of-service, credential attacks, spam, social engineering, malware, persistence, destructive exploitation, bulk extraction, or access to real user data. Use test accounts, your own data, and program-approved proof methods.

This cheatsheet is built around two HackerOne datasets:

1. **CWE Discovery**: HackerOne's CWE discovery pages group disclosed Hacktivity reports by weakness class. These pages are useful for hunting strategy because they reveal recurring weakness categories that researchers keep finding in real programs.
2. **CVE Discovery**: HackerOne's CVE discovery pages rank CVEs by recency and instances and include EPSS data. These pages are useful for prioritizing safe version-validation and patch-gap hunting, especially when programs explicitly allow CVE or known-vulnerability reporting.

The goal is not to blindly chase the most common bug classes. The goal is to find **manual niches**: areas that are common enough to be present across many programs, but nuanced enough that automated scanners often miss the specific impact. In practice, that means: authorization edge cases, object/property-level access control, workflow bypass, session boundary mistakes, password reset edge cases, API inventory mistakes, URL parser mismatches, file-processing logic, webhook/callback trust, cache behavior, open redirect chains, OAuth/OIDC implementation mistakes, request routing discrepancies, and CVE patch gaps that can be validated without weaponizing an exploit.

Throughout this document:

- **Unauthenticated testing** means you do not need an account, or you only interact with public endpoints and public assets.
- **Authenticated testing** means you use one or more accounts that you control. For authorization testing, two accounts are usually the minimum. Three accounts are better: low-privileged user, peer user, and elevated/organization-admin test user if the program allows role creation.
- **Impact-first reporting** means every finding must answer: *what can I read, change, trigger, bypass, or spend that I should not be able to?*
- **Informative-only traps** are called out so you do not waste reports on weak findings that typically get closed as not applicable, duplicate, accepted risk, or best-practice only.

> Practical mindset: HackerOne CWE/CVE discovery is not a payload list. Treat it as a map of where real researchers repeatedly found business-impactful flaws. Your advantage is careful manual comparison: role A vs role B, object X vs object Y, step 1 vs step 3, browser vs API, current version vs old version, cache miss vs cache hit, and intended callback domain vs attacker-controlled callback domain.



<div style='page-break-after: always;'></div>



## Table of Contents

1. How to use HackerOne CWE Discovery without chasing noise
2. How to use HackerOne CVE Discovery safely
3. Core manual testing setup
4. Evidence standards that avoid informative reports
5. CWE-driven niche hunting playbooks
6. CVE-driven patch-gap hunting playbooks
7. Authenticated testing matrix
8. Unauthenticated testing matrix
9. Report-writing templates
10. Tooling appendix
11. Source links

---

## How to use this document

Do not read this as a start-to-finish textbook. Use it like a field manual:

- When testing an API-heavy target, start with **CWE-639**, **CWE-862**, **CWE-863**, **CWE-915**, **CWE-20**, **CWE-400**, **CWE-352**, **CWE-918**, and **CWE-601**.
- When testing an account-heavy SaaS target, start with **CWE-287**, **CWE-288**, **CWE-307**, **CWE-384**, **CWE-613**, **CWE-640**, **CWE-352**, **CWE-639**, and **CWE-862**.
- When testing a file-processing app, start with **CWE-434**, **CWE-22**, **CWE-35**, **CWE-73**, **CWE-79**, **CWE-611**, **CWE-502**, **CWE-918**, and **CWE-400**.
- When testing a developer/platform product, start with **CWE-798**, **CWE-321**, **CWE-312**, **CWE-522**, **CWE-532**, **CWE-200**, **CWE-201**, **CWE-359**, **CWE-346**, **CWE-345**, **CWE-610**, **CWE-829**, and **CWE-494**.
- When testing infrastructure-adjacent web apps, start with **CWE-444**, **CWE-93**, **CWE-113**, **CWE-918**, **CWE-295**, **CWE-601**, **CWE-610**, **CWE-829**, and safe **CVE version validation**.

The most important rule: **do not report a class name; report impact**. "CWE-639" is not a report. "A member of Organization A can change the billing email of Organization B by replacing `org_id` in `PATCH /api/billing/profile`, causing account takeover of billing communications" is a report.

## What counts as a worthwhile bug here?

A finding is usually worth reporting when it demonstrates at least one of these outcomes using only permitted testing:

- unauthorized read of private data that belongs to another user, organization, tenant, project, repository, workspace, order, invoice, ticket, message, or file;
- unauthorized modification of data or configuration;
- privilege escalation, role escalation, or bypass of admin-only restrictions;
- account takeover or realistic account recovery bypass using accounts you own;
- bypass of payment, quota, approval, verification, licensing, or onboarding controls;
- sensitive token, secret, credential, or signing key exposure;
- server-side outbound request to an attacker-controlled endpoint from an in-scope server, proven safely;
- safe proof of vulnerable known software where the program accepts CVE reports and the affected version is exposed;
- clear chain impact, such as open redirect to OAuth code theft, CORS misconfiguration to data read, or XSS in privileged context.

A finding is often **informative-only** unless you can show impact:

- missing generic headers with no exploit path;
- self-XSS without a realistic victim path;
- open redirect with no security-sensitive chain and no program acceptance;
- version disclosure with no affected CVE and no exposure;
- rate limiting weakness on a non-sensitive endpoint;
- CSRF on logout, language preference, or other no-impact state change;
- reflected HTML that cannot execute or alter security-sensitive content;
- weak TLS configuration without exploitability under the program's rules;
- public information exposure that was already intentionally public;
- scanner-only CVE detection without confirming product, version, scope, and impact.



<div style='page-break-after: always;'></div>



# Core Manual Testing Setup

## Accounts and roles

Create a clean test structure before you hunt:

- **Account A**: primary attacker-controlled user.
- **Account B**: peer victim-controlled user. Use a different email, browser profile, and organization/workspace where possible.
- **Account C**: admin or owner test account, if the app allows you to create organizations and invite users.
- **Organization 1 and Organization 2**: separate tenants. Many high-value access control bugs only appear across tenant boundaries, not just across users in the same tenant.
- **Role pairs**: owner vs admin, admin vs member, member vs guest, guest vs pending invite, suspended vs active, paid vs free, trial vs expired, verified vs unverified.

Use different browser profiles or containers so cookies never mix. Firefox Multi-Account Containers, Chrome profiles, and Burp's session handling rules are useful here. Keep a small spreadsheet or notes file mapping every object ID you create: user IDs, org IDs, workspace IDs, project IDs, invoice IDs, file IDs, invite IDs, API keys, webhook IDs, SSO connection IDs, report IDs, and notification IDs.

## Proxy workflow

A productive manual workflow looks like this:

1. Browse the app normally as Account A while proxying through Burp, Caido, or OWASP ZAP.
2. Repeat the same workflow as Account B.
3. Compare requests and responses side by side.
4. Identify object identifiers, role flags, state tokens, hidden fields, GraphQL variables, JSON properties, headers, and path components.
5. Replay Account A's request with Account B's identifiers, then Account B's request with Account A's identifiers.
6. Strip optional fields and replay.
7. Add forbidden fields and replay.
8. Change method, path normalization, case, trailing slash, content type, and version prefix.
9. Confirm whether the server-side state changed, not just whether the response looked different.
10. Stop before accessing real third-party data. Use your own accounts and own objects.

## Minimum toolset

Manual does not mean no tools. It means tools support thinking rather than replacing it.

- **Burp Suite / Caido / OWASP ZAP**: intercept, replay, compare, organize, and document requests.
- **Browser DevTools**: inspect JavaScript bundles, storage, network calls, source maps, CORS behavior, cookies, and service workers.
- **jq**: compare JSON responses quickly.
- **diff tools**: compare Account A vs Account B responses.
- **httpx / curl / hurl**: reproduce requests cleanly.
- **ffuf / feroxbuster / gobuster**: content discovery only when allowed and rate-limited.
- **gau / waybackurls / katana / hakrawler**: endpoint discovery from public history and crawlable app surfaces.
- **arjun / param-miner**: parameter discovery, carefully throttled.
- **Interactsh / Burp Collaborator**: safe out-of-band callbacks for SSRF, blind XSS, blind XXE, webhook validation, and email/link rendering checks.
- **jwt_tool / jose tools / jwt.io**: inspect JWT structure, claims, algorithms, expiry, and key IDs. Do not brute force secrets unless explicitly allowed.
- **Wappalyzer / WhatWeb / builtwith-style inspection**: technology fingerprinting for CVE triage.
- **Nuclei**: use only non-invasive templates and only where automation is permitted. Treat output as a lead, not proof.
- **TruffleHog / Gitleaks**: only against in-scope repos/assets. Do not scan unrelated GitHub orgs unless the program allows it.
- **Semgrep**: useful for local code review or open-source targets when the program permits source review.

## Evidence notes

For every potential bug, capture:

- exact endpoint and method;
- the accounts/roles used;
- before-and-after screenshots or response snippets;
- request/response pairs with secrets redacted;
- why the accessed object belongs to another account/tenant;
- why the action should have been forbidden;
- what business or security impact follows;
- the smallest safe proof of concept that demonstrates impact without harming users.



<div style='page-break-after: always;'></div>


## HackerOne CWE Discovery Strategy: How to Find Niches

HackerOne's CWE discovery pages are useful because they translate public Hacktivity into weakness classes. Search snippets for the discovery pages show recurring categories such as cross-site scripting, authorization bypass through user-controlled key, improper authentication, violation of secure design principles, open redirect, CSRF, SQL injection, code injection, SSRF, missing authorization, improper input validation, excessive authentication attempts, resource consumption, insecure storage, external resource references, and request/response smuggling.

The strategic mistake is to hunt only the highest-count classes. The highest-count classes are crowded. Instead, combine three dimensions:

1. **Frequency**: does the class appear often enough that many modern apps have it?
2. **Manual advantage**: can a careful human find it better than a scanner?
3. **Reportability**: does the class usually produce clear impact rather than informative noise?

The best niches sit in the intersection. For example:

- **CWE-639 + CWE-862 + CWE-863**: object/function authorization is frequent, manual, and high impact.
- **CWE-915 + CWE-20**: mass assignment and business validation are manual and often missed.
- **CWE-384 + CWE-613 + CWE-640**: session/recovery state bugs need multi-browser testing and produce account security impact.
- **CWE-918 + CWE-610 + CWE-346**: URL/callback trust bugs are feature-specific and often missed by generic scanners.
- **CWE-444 + CWE-93**: protocol/parser mismatches are niche and high-impact but must be tested safely and only when allowed.
- **CWE-798 + CWE-321 + CWE-532**: exposed secrets are common, but only valuable when you prove capability.
- **CWE-367 + CWE-400**: race/resource bugs are valuable when shown with tiny safe proofs and business impact, not stress tests.

A strong hunting session should begin by asking: *Where does the application make a trust decision?* Every bug class in this cheatsheet is a failure of a trust decision. The server trusts a user-supplied ID, a client-supplied role, a stale session, a callback domain, a webhook signature, a file extension, a serialized object, a redirect parameter, a parser interpretation, a cached response, or a displayed version.


<div style='page-break-after: always;'></div>


## HackerOne CVE Discovery Strategy: Safe Known-Vulnerability Hunting

HackerOne's CVE discovery pages rank CVEs by recency and instances and include EPSS context. This is valuable, but it must be used carefully. A CVE is a public vulnerability identifier, not automatically a valid bounty report. Programs vary: some accept known CVEs on in-scope assets, some only accept if exploitation is proven safely, and some reject known issues if they are already tracked or managed by the vendor.

A safe CVE-hunting process:

1. **Policy check**: confirm the program accepts known vulnerability reports, automation, version checks, and non-invasive validation.
2. **Asset scope check**: confirm the host, path, app, subdomain, mobile app, repository, or cloud asset is in scope.
3. **Product identity**: confirm the software/component with two independent signals when possible.
4. **Version proof**: confirm the deployed version, build, plugin version, package version, or static asset version.
5. **Advisory mapping**: confirm the CVE affects that version and component.
6. **Reachability**: confirm the vulnerable feature is reachable or enabled. A vulnerable library sitting unused is weak.
7. **Safe validation**: use benign probes, version checks, or controlled canaries. Avoid weaponized exploit payloads unless the program explicitly allows them.
8. **Impact explanation**: explain what the CVE enables in this deployment and what an attacker would need.
9. **Remediation**: specify fixed version or mitigation.

The biggest CVE-reporting mistakes are: relying only on a scanner, reporting a CVE for an out-of-scope host, proving only a version string, using a public exploit destructively, ignoring that the vulnerable feature is disabled, or failing to show that the app actually uses the affected component.


<div style='page-break-after: always;'></div>


## Authenticated vs Unauthenticated Matrix

## Unauthenticated high-yield areas

- Public API routes exposing object IDs or private data.
- Signup, login, password reset, magic link, OTP, and SSO initiation.
- Public file downloads, share links, public profiles, public search, public organization pages.
- Redirect parameters in login, SSO, marketing links, OAuth authorization, and invite flows.
- URL fetchers that do not require login: link preview, image proxy, feed import, screenshot tool.
- Public version exposure: CMS, plugins, static assets, admin panels, error pages, documentation.
- CORS and postMessage issues only if private data or credentials are involved.
- Exposed backups, source maps, `.git`, `.env`, logs, debug endpoints.

## Authenticated high-yield areas

- Cross-tenant object access with two accounts.
- Role-based admin/member/guest bypass.
- Billing, subscription, plan, trial, quota, credits, coupons, refunds, invoices.
- User management: invites, role changes, removals, transfers, pending members.
- Organization settings: SSO, SCIM, webhooks, API keys, audit logs, custom domains.
- File features: upload, preview, share, export, import, archive extraction.
- Integrations: OAuth, webhooks, Slack/Jira/GitHub/GitLab, SAML metadata, inbound email.
- Session lifecycle: logout, password reset, MFA change, email change, role removal.
- GraphQL and mobile APIs: property-level access, hidden fields, old endpoints.

## Best manual loop

For every feature, perform this loop:

1. Use the UI normally.
2. Capture the API request.
3. Repeat as another role/user/tenant.
4. Diff the requests and responses.
5. Change one boundary variable.
6. Remove one security token.
7. Add one forbidden property.
8. Replay after a state transition.
9. Verify server-side effect.
10. Convert into minimal safe proof.


<div style='page-break-after: always;'></div>


## CWE-639 — Authorization Bypass Through User-Controlled Key

**Niche:** IDOR/BOLA in APIs, GraphQL, mobile APIs, tenant IDs, billing IDs, invite IDs, object IDs hidden in responses.

**Why this is worth hunting:** HackerOne snippets show this as a high-volume category, and it is one of the most manually profitable because the test is comparison rather than exploitation.

### Unauthenticated angle

Look for public endpoints that expose numeric IDs, slugs, UUIDs, short IDs, invite tokens, share links, order references, public GraphQL nodes, or predictable CDN paths. Unauthenticated IDOR is rarer but high impact when public token entropy is weak or resources are accidentally public.

### Authenticated angle

Use two accounts and two tenants. Create equivalent objects under each. Capture every request that reads, updates, deletes, exports, invites, bills, comments, downloads, shares, archives, restores, transfers, approves, rejects, or changes visibility. Replace only one identifier at a time.

### Manual testing workflow

1. Create object A under Account A and object B under Account B.
2. Replay Account A's read request with object B's ID while keeping Account A's cookie/token.
3. Repeat for write actions: update title, change email, add comment, archive, delete, invite, export, rotate key, regenerate token.
4. Test nested IDs: `/orgs/{org_id}/projects/{project_id}/files/{file_id}`. Keep project ID valid but swap file ID; then keep file ID valid but swap org ID.
5. Test GraphQL: change `id`, `nodeId`, `ownerId`, `organizationId`, `resourceId`, `viewerId`, and variables inside nested input objects.
6. Test indirect references: export jobs, report downloads, invoices, notification IDs, signed file URLs, webhook delivery IDs, audit log IDs.
7. Check whether 403/302 responses still include private data in the body.
8. Confirm server-side state changed by refreshing the victim-controlled account, not just by reading the API response.


### What makes the report strong

Unauthorized cross-user or cross-tenant read/write. Strong reports show sensitive fields, state-changing actions, role changes, billing changes, file downloads, or administrative actions.

### What usually becomes informative or rejected

Do not report changing your own ID to your own other account if both accounts are in the same intentionally shared organization unless the permission boundary is clear. Do not bulk enumerate. Do not access real user data.

### Useful tools

Burp Repeater/Comparer, Autorize/Bambdas-style authorization checks, Caido Replay, jq, GraphQL Voyager where introspection is permitted, browser DevTools.

### Extra manual heuristics

- Look for the same operation exposed through more than one route. Modern apps often have REST, GraphQL, mobile, admin, and internal-feeling routes for the same action.
- Try the bug after state changes: user removed, role downgraded, subscription expired, invitation revoked, token rotated, email changed, password reset, object archived, object transferred.
- Compare not only status code but also response body, response size, cache headers, timing, side effects, notifications, audit logs, and background jobs.
- For every successful-looking response, verify in the victim-controlled account whether the private state actually changed.
- Prefer proof with your own objects and tenants. If a bug would expose real user data, stop at the first safe indicator and explain the risk without accessing third-party data.


<div style='page-break-after: always;'></div>


## CWE-862 — Missing Authorization

**Niche:** Endpoints that require login but no permission check for specific action/resource.

**Why this is worth hunting:** This is the root of many BOLA/BFLA bugs. It appears heavily in HackerOne discovery snippets and maps directly to OWASP API object/function authorization risks.

### Unauthenticated angle

Find endpoints that work without a cookie even though the UI requires login. Check exported JS routes, API docs, mobile endpoints, old versions, and endpoints returning `200` with private state after logout.

### Authenticated angle

Use a low-privileged account to call endpoints only visible to owner/admin. Try direct API calls for hidden UI actions.

### Manual testing workflow

1. Open the same sensitive endpoint logged in and logged out; compare status code, body, and side effects.
2. Remove `Authorization` header but keep other headers; then remove cookies but keep CSRF token; then test a fresh browser session.
3. Call owner/admin endpoints as a member/guest/pending user.
4. Try alternative methods where safe: `GET` vs `POST`, `PATCH` vs `PUT`, `DELETE` vs `POST /delete`.
5. Use path variants: trailing slash, mixed case, URL-encoded path segments, old API prefix, `/api/internal/`, `/admin/api/`, `/v1/` vs `/v2/`.
6. Check async endpoints: export job creation may be protected but download job result may not be.
7. Check file endpoints: metadata endpoint may be protected but raw file URL may not be.


### What makes the report strong

Unauthorized action or private data access without required authorization. Best when it crosses role, tenant, or authentication boundaries.

### What usually becomes informative or rejected

A 401/403 bypass must expose data or perform action. An endpoint merely returning a generic 200 or error message is not enough.

### Useful tools

Burp Repeater, logout/fresh profile testing, ffuf for route discovery where allowed, route extraction from JS bundles.

### Extra manual heuristics

- Look for the same operation exposed through more than one route. Modern apps often have REST, GraphQL, mobile, admin, and internal-feeling routes for the same action.
- Try the bug after state changes: user removed, role downgraded, subscription expired, invitation revoked, token rotated, email changed, password reset, object archived, object transferred.
- Compare not only status code but also response body, response size, cache headers, timing, side effects, notifications, audit logs, and background jobs.
- For every successful-looking response, verify in the victim-controlled account whether the private state actually changed.
- Prefer proof with your own objects and tenants. If a bug would expose real user data, stop at the first safe indicator and explain the risk without accessing third-party data.


<div style='page-break-after: always;'></div>


## CWE-863 — Incorrect Authorization

**Niche:** Authorization checks exist but evaluate the wrong user, wrong object, wrong tenant, wrong step, or wrong role.

**Why this is worth hunting:** This category captures the bugs that scanners miss because the endpoint appears protected but the business rule is wrong.

### Unauthenticated angle

Look for tokenized flows where possession of a link grants too much authority: invites, password reset, email verification, magic link, unsubscribe, export downloads, shared documents.

### Authenticated angle

Build a permission matrix and test every action across roles and object ownership. Especially test member-to-admin, guest-to-member, expired-to-active, and pending-to-accepted transitions.

### Manual testing workflow

1. List every role and action the UI exposes.
2. For each action, ask what object and tenant the server should check.
3. Replay requests from the wrong role and wrong tenant.
4. Test stale permissions: create a token/link as admin, downgrade user, reuse the old token/link.
5. Test state-dependent checks: skip approval, skip checkout, skip verification, perform final confirmation directly.
6. Test copied requests after leaving an org or being removed from a project.
7. Test webhook/API key scopes: key created for read-only use performing write actions.


### What makes the report strong

Privilege escalation, unauthorized action, workflow bypass, stale authorization token reuse.

### What usually becomes informative or rejected

Do not rely only on UI hiding as proof. The server behavior is what matters.

### Useful tools

Role matrix spreadsheet, Burp collections, Postman/Insomnia for API workflows, browser profiles.

### Extra manual heuristics

- Look for the same operation exposed through more than one route. Modern apps often have REST, GraphQL, mobile, admin, and internal-feeling routes for the same action.
- Try the bug after state changes: user removed, role downgraded, subscription expired, invitation revoked, token rotated, email changed, password reset, object archived, object transferred.
- Compare not only status code but also response body, response size, cache headers, timing, side effects, notifications, audit logs, and background jobs.
- For every successful-looking response, verify in the victim-controlled account whether the private state actually changed.
- Prefer proof with your own objects and tenants. If a bug would expose real user data, stop at the first safe indicator and explain the risk without accessing third-party data.


<div style='page-break-after: always;'></div>


## CWE-287 — Improper Authentication

**Niche:** Login, SSO, magic link, OAuth/OIDC, device login, API token auth, mobile auth, account linking.

**Why this is worth hunting:** HackerOne search snippets show improper authentication as a major category. High-impact auth bugs are often edge cases in alternate login paths, not the main password form.

### Unauthenticated angle

Enumerate all auth entry points: email/password, phone OTP, social login, enterprise SSO, magic link, passkey, device code, QR login, mobile deep link, invitation acceptance, account recovery.

### Authenticated angle

Test session issuance and account linking while already logged in. Many auth bugs happen when a logged-in user connects another identity provider or accepts an invite.

### Manual testing workflow

1. Map all login routes and identity providers.
2. Try starting auth as Account A and completing with Account B only where both accounts are yours.
3. Check whether `state`, `nonce`, `redirect_uri`, `code_verifier`, `email`, `user_id`, `tenant`, and `provider` are bound to the initiating session.
4. Test account linking: can a provider identity be linked to the wrong existing account?
5. Test invitation login: can invite acceptance authenticate the wrong email?
6. Test magic links: can links be reused, used after email change, or used after logout/password reset?
7. Check device login/QR: can a code approved by one account authenticate another browser?
8. Check error messages for user enumeration only when program accepts it; otherwise treat as low value.


### What makes the report strong

Account takeover, authentication bypass, login CSRF, account linking takeover, tenant SSO bypass.

### What usually becomes informative or rejected

Do not brute force OTPs or passwords. Do not attack real accounts. Do not report cosmetic login errors without takeover or bypass.

### Useful tools

Burp, browser profiles, JWT inspector, OAuth debugger, mobile proxy if permitted.

### Extra manual heuristics

- Look for the same operation exposed through more than one route. Modern apps often have REST, GraphQL, mobile, admin, and internal-feeling routes for the same action.
- Try the bug after state changes: user removed, role downgraded, subscription expired, invitation revoked, token rotated, email changed, password reset, object archived, object transferred.
- Compare not only status code but also response body, response size, cache headers, timing, side effects, notifications, audit logs, and background jobs.
- For every successful-looking response, verify in the victim-controlled account whether the private state actually changed.
- Prefer proof with your own objects and tenants. If a bug would expose real user data, stop at the first safe indicator and explain the risk without accessing third-party data.


<div style='page-break-after: always;'></div>


## CWE-288 — Authentication Bypass Using Alternate Path or Channel

**Niche:** Old endpoints, mobile-only APIs, SSO bypass routes, legacy admin paths, alternate content types.

**Why this is worth hunting:** Alternate paths are ideal manual niches because the main UI can be secure while an older endpoint remains exposed.

### Unauthenticated angle

Look for legacy routes in JS bundles, archived docs, mobile app traffic, old API versions, `/api/v1`, `/legacy`, `/mobile`, `/internal`, `/admin`, `/oauth/callback`, and CDN-hosted apps.

### Authenticated angle

Use a normal account to access routes meant for SSO-admin, enterprise-only, staff-only, or paid-only channels.

### Manual testing workflow

1. Find the canonical protected route.
2. Search for alternate routes that perform the same action.
3. Test path aliases, old version prefixes, mobile endpoints, and JSON-RPC/GraphQL equivalents.
4. Test content type switching: JSON endpoint vs multipart endpoint vs form endpoint.
5. Test frontend route guards vs direct API calls.
6. Test whether authentication middleware is missing on subrouters or specific methods.


### What makes the report strong

Bypass of login or enterprise SSO, access to admin or internal function, paid feature bypass.

### What usually becomes informative or rejected

Directory listing or route existence alone is not enough. Demonstrate protected action/data.

### Useful tools

Route extraction, Burp, ffuf with low rate where allowed, APK/API traffic review where allowed.

### Extra manual heuristics

- Look for the same operation exposed through more than one route. Modern apps often have REST, GraphQL, mobile, admin, and internal-feeling routes for the same action.
- Try the bug after state changes: user removed, role downgraded, subscription expired, invitation revoked, token rotated, email changed, password reset, object archived, object transferred.
- Compare not only status code but also response body, response size, cache headers, timing, side effects, notifications, audit logs, and background jobs.
- For every successful-looking response, verify in the victim-controlled account whether the private state actually changed.
- Prefer proof with your own objects and tenants. If a bug would expose real user data, stop at the first safe indicator and explain the risk without accessing third-party data.


<div style='page-break-after: always;'></div>


## CWE-307 — Improper Restriction of Excessive Authentication Attempts

**Niche:** OTP, password reset, invite acceptance, coupon/redeem codes, recovery codes, email change confirmation, MFA prompts.

**Why this is worth hunting:** HackerOne snippets show this class around thousands of reports. Many simple rate-limit findings are low severity, but auth and financial flows can be meaningful.

### Unauthenticated angle

Check whether rate limiting exists on login, forgot password, OTP verification, magic link send, username lookup, invite send, and code redemption. Stay within program rate limits and use only your own accounts.

### Authenticated angle

Test sensitive in-session flows: change email, disable MFA, rotate API key, transfer ownership, invite admin, redeem credits.

### Manual testing workflow

1. Identify the sensitive verification endpoint.
2. Send a tiny number of repeated wrong attempts to observe lockout behavior; do not brute force.
3. Check whether rate limit keying is by IP, account, email, session, device, org, or token.
4. Test bypass by changing casing, adding whitespace, changing content type, adding duplicate parameters, or switching endpoint versions.
5. Test whether requesting a new OTP invalidates the old one.
6. Test whether lockout on one endpoint applies to equivalent endpoints.
7. For report proof, demonstrate missing/weak throttling with a small bounded sample and explain attack feasibility without performing it.


### What makes the report strong

OTP bypass feasibility, account recovery risk, invite abuse, coupon abuse, business-flow abuse.

### What usually becomes informative or rejected

Do not brute force real codes. Do not send high-volume traffic. Rate limit on a harmless newsletter form is often informative or low.

### Useful tools

Burp Intruder with tiny safe counts, Repeater, manual timing, program-approved rate limits.

### Extra manual heuristics

- Look for the same operation exposed through more than one route. Modern apps often have REST, GraphQL, mobile, admin, and internal-feeling routes for the same action.
- Try the bug after state changes: user removed, role downgraded, subscription expired, invitation revoked, token rotated, email changed, password reset, object archived, object transferred.
- Compare not only status code but also response body, response size, cache headers, timing, side effects, notifications, audit logs, and background jobs.
- For every successful-looking response, verify in the victim-controlled account whether the private state actually changed.
- Prefer proof with your own objects and tenants. If a bug would expose real user data, stop at the first safe indicator and explain the risk without accessing third-party data.


<div style='page-break-after: always;'></div>


## CWE-384 — Session Fixation

**Niche:** Login does not rotate session identifiers; invite/magic flows bind attacker-created sessions; workspace creation from victim session.

**Why this is worth hunting:** HackerOne snippets include session fixation examples. It is often missed because testers only check login success, not token lifecycle.

### Unauthenticated angle

Start with a fresh anonymous session, note cookies/local storage, then log in and verify whether security-sensitive tokens rotate.

### Authenticated angle

Test privilege changes, MFA enablement, password reset, email change, SSO login, organization switch, and impersonation-style support flows if allowed.

### Manual testing workflow

1. Record cookies before login.
2. Log in and compare all session cookies and local storage tokens.
3. Log out and check whether old tokens are invalidated.
4. Change password or enable MFA and test whether old sessions remain valid.
5. Create an invite or magic link in one browser and open it in another; check whether account/session binding is safe.
6. Test whether session IDs persist across privilege elevation or organization switching.


### What makes the report strong

Session takeover or persistence after account security events. Strong impact needs a way for attacker to set or reuse a victim session token.

### What usually becomes informative or rejected

Session not rotating on non-auth preference changes is not enough. Do not steal or use anyone else's session.

### Useful tools

Browser profiles, cookie editor, Burp, DevTools Application tab.

### Extra manual heuristics

- Look for the same operation exposed through more than one route. Modern apps often have REST, GraphQL, mobile, admin, and internal-feeling routes for the same action.
- Try the bug after state changes: user removed, role downgraded, subscription expired, invitation revoked, token rotated, email changed, password reset, object archived, object transferred.
- Compare not only status code but also response body, response size, cache headers, timing, side effects, notifications, audit logs, and background jobs.
- For every successful-looking response, verify in the victim-controlled account whether the private state actually changed.
- Prefer proof with your own objects and tenants. If a bug would expose real user data, stop at the first safe indicator and explain the risk without accessing third-party data.


<div style='page-break-after: always;'></div>


## CWE-613 — Insufficient Session Expiration

**Niche:** Old sessions remain valid after logout, password reset, MFA enablement, role removal, account deletion, SSO deprovisioning.

**Why this is worth hunting:** This is especially useful in SaaS and enterprise programs where account lifecycle matters.

### Unauthenticated angle

Not usually applicable except public tokenized links that should expire.

### Authenticated angle

Use Account A in two browsers. Perform security event in one browser, then test old token in the other.

### Manual testing workflow

1. Log in from Browser 1 and Browser 2.
2. Change password, reset password, enable MFA, disable API key, leave org, remove member, or delete account from Browser 1.
3. Replay sensitive requests from Browser 2 using the old token.
4. Test access to API as well as UI. UIs often redirect but API tokens still work.
5. Test refresh token behavior: can an old refresh token mint new access tokens after revocation?


### What makes the report strong

Persistence after account compromise remediation, ex-employee access, stale admin powers.

### What usually becomes informative or rejected

Long session lifetime alone may be accepted risk. Tie to a security event that should revoke access.

### Useful tools

Two browser profiles, Burp, JWT inspection, token refresh testing.

### Extra manual heuristics

- Look for the same operation exposed through more than one route. Modern apps often have REST, GraphQL, mobile, admin, and internal-feeling routes for the same action.
- Try the bug after state changes: user removed, role downgraded, subscription expired, invitation revoked, token rotated, email changed, password reset, object archived, object transferred.
- Compare not only status code but also response body, response size, cache headers, timing, side effects, notifications, audit logs, and background jobs.
- For every successful-looking response, verify in the victim-controlled account whether the private state actually changed.
- Prefer proof with your own objects and tenants. If a bug would expose real user data, stop at the first safe indicator and explain the risk without accessing third-party data.


<div style='page-break-after: always;'></div>


## CWE-640 — Weak Password Recovery Mechanism

**Niche:** Reset token reuse, token not tied to email/session, missing invalidation, host header poisoning in reset links, reset flow account confusion.

**Why this is worth hunting:** Password reset remains high value and manual testing catches state bugs that scanners cannot reason about.

### Unauthenticated angle

Request resets for your own accounts. Inspect reset link parameters, host, token expiry, reuse, account binding, and email change interactions.

### Authenticated angle

Test reset while logged in, while changing email, while linked to SSO, after account deletion, and after MFA changes.

### Manual testing workflow

1. Request two reset links; verify whether the first is invalidated after the second.
2. Use reset link once; verify it cannot be reused.
3. Change email after requesting reset; verify old reset link cannot reset new identity incorrectly.
4. Check token length and entropy superficially; do not brute force.
5. Test host/header influence only on your own email: `Host`, `X-Forwarded-Host`, `X-Forwarded-Proto` where permitted.
6. Test whether reset completion logs out existing sessions.
7. Test whether SSO-only accounts can be converted into password accounts unexpectedly.


### What makes the report strong

Account takeover, login bypass, reset link hijack, session persistence after reset.

### What usually becomes informative or rejected

Do not request resets for real users. User enumeration only is usually low unless explicitly accepted.

### Useful tools

Burp, email inbox you control, browser profiles, link scanner disabled.

### Extra manual heuristics

- Look for the same operation exposed through more than one route. Modern apps often have REST, GraphQL, mobile, admin, and internal-feeling routes for the same action.
- Try the bug after state changes: user removed, role downgraded, subscription expired, invitation revoked, token rotated, email changed, password reset, object archived, object transferred.
- Compare not only status code but also response body, response size, cache headers, timing, side effects, notifications, audit logs, and background jobs.
- For every successful-looking response, verify in the victim-controlled account whether the private state actually changed.
- Prefer proof with your own objects and tenants. If a bug would expose real user data, stop at the first safe indicator and explain the risk without accessing third-party data.


<div style='page-break-after: always;'></div>


## CWE-352 — Cross-Site Request Forgery

**Niche:** High-impact state changes still using cookie auth without CSRF protections, especially JSON endpoints accepting simple content types or GET-based actions.

**Why this is worth hunting:** HackerOne snippets show CSRF as a high-volume category, but many CSRF reports are rejected unless the action matters.

### Unauthenticated angle

Not normally applicable because CSRF abuses a victim's authenticated browser. Public endpoints can be abused for spam but that is not classic CSRF.

### Authenticated angle

Focus on email change, password change, MFA disable, invite admin, transfer ownership, payment method change, webhook change, API key creation, OAuth app authorization, notification forwarding, privacy settings.

### Manual testing workflow

1. Identify a sensitive state-changing request that uses cookies.
2. Remove CSRF token and replay. Then replace token with another account's token. Then use a stale token.
3. Check whether SameSite cookies mitigate the attack, but remember SameSite is not a substitute for all CSRF cases.
4. Try simple forms only for proof. Do not trigger harmful side effects on real accounts.
5. Check content type: some JSON endpoints accept `text/plain` or form-encoded bodies.
6. Check GET actions, method override, `_method=DELETE`, and endpoints that ignore method.
7. Build a minimal local HTML proof against your own account only.


### What makes the report strong

Victim account state change. Strong if it changes credentials, MFA, email, billing, admin membership, or security settings.

### What usually becomes informative or rejected

Logout CSRF, language/theme changes, and self-contained low-impact settings are often informative.

### Useful tools

Burp, local HTML page, browser profiles, CSRF PoC generator.

### Extra manual heuristics

- Look for the same operation exposed through more than one route. Modern apps often have REST, GraphQL, mobile, admin, and internal-feeling routes for the same action.
- Try the bug after state changes: user removed, role downgraded, subscription expired, invitation revoked, token rotated, email changed, password reset, object archived, object transferred.
- Compare not only status code but also response body, response size, cache headers, timing, side effects, notifications, audit logs, and background jobs.
- For every successful-looking response, verify in the victim-controlled account whether the private state actually changed.
- Prefer proof with your own objects and tenants. If a bug would expose real user data, stop at the first safe indicator and explain the risk without accessing third-party data.


<div style='page-break-after: always;'></div>


## CWE-79 — Cross-Site Scripting

**Niche:** Stored XSS in privileged views, DOM XSS in modern frontends, markdown/rendering, file preview, link unfurling, PDF/image metadata, admin dashboards.

**Why this is worth hunting:** HackerOne snippets show XSS as the largest discovery category. The niche is not generic alert boxes; it is high-context execution with meaningful victim reach.

### Unauthenticated angle

Test public search, marketing pages, redirect parameters, share links, public profiles, public docs, public file previews, URL fragment-driven SPAs.

### Authenticated angle

Test every text field rendered to another user or admin: names, org names, project titles, comments, file names, custom fields, markdown, support tickets, invoices, webhooks, audit logs, notification templates.

### Manual testing workflow

1. Map input-output pairs: where does each field appear after saving?
2. Test harmless proof payloads such as a visual marker or `alert(document.domain)` only in your own account/context.
3. Identify output context: HTML body, attribute, URL, JavaScript string, template literal, Markdown, SVG, PDF preview, email.
4. Check sanitization differences between create, edit, import, API, mobile, and bulk upload.
5. Test privileged renderers: admin panel, moderation queue, billing invoice, support dashboard, analytics export.
6. Check DOM sinks by watching client-side route parameters, hash fragments, postMessage handlers, and localStorage values.
7. For impact, show execution in another controlled account or a privileged test role, not just self-XSS.


### What makes the report strong

Account action as victim, token exposure if accessible, privileged admin action, stored execution in support/admin context, OAuth/CSRF chaining.

### What usually becomes informative or rejected

Self-XSS, CSP bypass without injection, and harmless HTML injection are often rejected unless chained.

### Useful tools

Burp, DOM Invader, DevTools, markdown preview, Interactsh for blind callbacks where allowed.

### Extra manual heuristics

- Look for the same operation exposed through more than one route. Modern apps often have REST, GraphQL, mobile, admin, and internal-feeling routes for the same action.
- Try the bug after state changes: user removed, role downgraded, subscription expired, invitation revoked, token rotated, email changed, password reset, object archived, object transferred.
- Compare not only status code but also response body, response size, cache headers, timing, side effects, notifications, audit logs, and background jobs.
- For every successful-looking response, verify in the victim-controlled account whether the private state actually changed.
- Prefer proof with your own objects and tenants. If a bug would expose real user data, stop at the first safe indicator and explain the risk without accessing third-party data.


<div style='page-break-after: always;'></div>


## CWE-601 — Open Redirect

**Niche:** Redirects that can steal OAuth codes, magic links, SSO tokens, post-login destinations, or trusted-domain flows.

**Why this is worth hunting:** HackerOne snippets show open redirect as common. Standalone open redirect is often low, but redirect chains are valuable.

### Unauthenticated angle

Search for `next`, `return`, `redirect`, `continue`, `url`, `target`, `destination`, `callback`, `relayState`, `returnTo`, and `service` parameters in public endpoints.

### Authenticated angle

Test post-login redirects, SSO RelayState, OAuth redirect flows, email verification, invite acceptance, and checkout/payment returns.

### Manual testing workflow

1. Confirm the endpoint redirects to a URL you control.
2. Test allowlist bypasses carefully: scheme-relative URLs, encoded slashes, backslashes, subdomain confusion, userinfo, dot segments, mixed case, nested redirects.
3. Check whether the redirect parameter is used after login, after OAuth authorization, or inside emailed links.
4. Try chaining only with your own accounts: OAuth code leakage, magic link forwarding, token in URL fragment, SSO RelayState confusion.
5. Document why the redirect is security-sensitive.


### What makes the report strong

Credential/token/code leakage, phishing through trusted domain, auth flow compromise. Strong reports include a chain.

### What usually becomes informative or rejected

Plain open redirect on a non-sensitive endpoint may be informative/low depending on policy.

### Useful tools

Burp, browser DevTools, URL parser test notes, OAuth test app you control if permitted.

### Extra manual heuristics

- Look for the same operation exposed through more than one route. Modern apps often have REST, GraphQL, mobile, admin, and internal-feeling routes for the same action.
- Try the bug after state changes: user removed, role downgraded, subscription expired, invitation revoked, token rotated, email changed, password reset, object archived, object transferred.
- Compare not only status code but also response body, response size, cache headers, timing, side effects, notifications, audit logs, and background jobs.
- For every successful-looking response, verify in the victim-controlled account whether the private state actually changed.
- Prefer proof with your own objects and tenants. If a bug would expose real user data, stop at the first safe indicator and explain the risk without accessing third-party data.


<div style='page-break-after: always;'></div>


## CWE-918 — Server-Side Request Forgery

**Niche:** URL fetchers, webhooks, import by URL, PDF/image renderers, link previews, integrations, cloud metadata-adjacent behavior.

**Why this is worth hunting:** HackerOne discovery snippets include SSRF as a recurring class. Manual SSRF hunting works because testers notice business features that make outbound requests.

### Unauthenticated angle

Look for public URL preview, image proxy, download by URL, OpenGraph fetch, webhook test, feed import, avatar URL, PDF generation from URL, screenshot services.

### Authenticated angle

Test integrations: webhook destinations, Jira/Slack/GitLab connectors, custom OAuth metadata, SAML metadata URL, SCIM endpoints, importers, repository URL fetchers.

### Manual testing workflow

1. Submit a URL to a domain you control or Interactsh/Burp Collaborator and confirm a server-side callback.
2. Record source IP, method, headers, DNS behavior, redirects, and timing.
3. Test whether redirects are followed to your controlled domain. Do not target internal IPs unless the program explicitly permits SSRF validation to internal assets.
4. Test parser confusion safely: allowed domain that redirects to your domain, URL-encoded host, mixed scheme, IPv6 literal to your own host, userinfo confusion.
5. Check whether response content is returned to the user, stored, included in generated PDF, or only blind.
6. Demonstrate impact through controlled data exfiltration from your own host, not internal scanning.
7. If cloud metadata testing is allowed, follow the program's SSRF proof rules exactly; otherwise do not attempt metadata access.


### What makes the report strong

Server-side network access, internal service access, cloud metadata exposure, webhook secret leakage, blind callback from sensitive network.

### What usually becomes informative or rejected

Do not port scan internal networks, hit metadata endpoints without permission, or cause high-volume callbacks.

### Useful tools

Burp Collaborator, Interactsh, controlled web server logs, webhook.site-like services if permitted.

### Extra manual heuristics

- Look for the same operation exposed through more than one route. Modern apps often have REST, GraphQL, mobile, admin, and internal-feeling routes for the same action.
- Try the bug after state changes: user removed, role downgraded, subscription expired, invitation revoked, token rotated, email changed, password reset, object archived, object transferred.
- Compare not only status code but also response body, response size, cache headers, timing, side effects, notifications, audit logs, and background jobs.
- For every successful-looking response, verify in the victim-controlled account whether the private state actually changed.
- Prefer proof with your own objects and tenants. If a bug would expose real user data, stop at the first safe indicator and explain the risk without accessing third-party data.


<div style='page-break-after: always;'></div>


## CWE-444 — HTTP Request/Response Smuggling

**Niche:** Proxy/backend parsing mismatches, HTTP/2 downgrade, CDN/WAF discrepancies, cache poisoning vectors.

**Why this is worth hunting:** HackerOne includes this CWE, and it is niche because it requires careful protocol testing rather than generic app payloads.

### Unauthenticated angle

Only test where program allows low-level HTTP/proxy testing. Start with safe timeout/desync probes, not harmful poisoning or victim capture.

### Authenticated angle

Authenticated request smuggling can bypass front-end auth or poison user-specific caches, but the proof must stay within your accounts.

### Manual testing workflow

1. Confirm the target architecture has an intermediary: CDN, reverse proxy, load balancer, WAF, API gateway.
2. Use a purpose-built tool or Burp extension in safe mode to detect CL/TE or HTTP/2 downgrade anomalies.
3. Prefer timing-based confirmation and self-contained canary endpoints.
4. Never attempt to capture other users' requests. Never poison shared caches with harmful content.
5. If a desync is suspected, prove impact against a route you control or a harmless endpoint.
6. Document exact protocol version, headers, front-end behavior, backend behavior, and whether the issue is reproducible.


### What makes the report strong

Front-end control bypass, cache poisoning, response queue desync, request routing confusion. Strong but sensitive class; keep proof safe.

### What usually becomes informative or rejected

Do not run aggressive smuggling scans. Do not target unrelated users. Many programs restrict this.

### Useful tools

Burp HTTP Request Smuggler, Turbo Intruder in safe mode, raw HTTP clients, curl with HTTP/2 flags for benign checks.

### Extra manual heuristics

- Look for the same operation exposed through more than one route. Modern apps often have REST, GraphQL, mobile, admin, and internal-feeling routes for the same action.
- Try the bug after state changes: user removed, role downgraded, subscription expired, invitation revoked, token rotated, email changed, password reset, object archived, object transferred.
- Compare not only status code but also response body, response size, cache headers, timing, side effects, notifications, audit logs, and background jobs.
- For every successful-looking response, verify in the victim-controlled account whether the private state actually changed.
- Prefer proof with your own objects and tenants. If a bug would expose real user data, stop at the first safe indicator and explain the risk without accessing third-party data.


<div style='page-break-after: always;'></div>


## CWE-93 / CWE-113 — CRLF Injection / HTTP Response Splitting

**Niche:** Header injection in redirects, downloads, filenames, proxy headers, email headers, cache keys, logs.

**Why this is worth hunting:** HackerOne snippets include CWE-93. It can become high impact when it causes cache poisoning, cookie injection, or header manipulation.

### Unauthenticated angle

Test reflected parameters in headers: redirect `Location`, `Set-Cookie`, `Content-Disposition`, `Link`, `Refresh`, custom headers, error pages.

### Authenticated angle

Test file downloads, export names, invoice names, org names, report titles, and webhook header configuration.

### Manual testing workflow

1. Find a response header that reflects user input.
2. Use harmless newline markers to see whether header splitting occurs; do not inject malicious cookies for real users.
3. Check encoded variants: `%0d%0a`, double encoding, Unicode normalization, CR-only/LF-only behavior.
4. Check whether intermediary/CDN normalizes differently from origin.
5. If header injection works, test safe impact: add a benign custom header, alter filename, or create a self-contained cache test on an unshared path.
6. Report only if you can show security impact: cache poison, cookie manipulation, redirect manipulation, CSP weakening, or response splitting.


### What makes the report strong

Response splitting, cache poisoning, cookie injection, security header manipulation, header-based XSS chain.

### What usually becomes informative or rejected

Header reflection without splitting or impact is often low/informative.

### Useful tools

Burp Repeater, curl `-v`, browser DevTools, cache-buster parameters.

### Extra manual heuristics

- Look for the same operation exposed through more than one route. Modern apps often have REST, GraphQL, mobile, admin, and internal-feeling routes for the same action.
- Try the bug after state changes: user removed, role downgraded, subscription expired, invitation revoked, token rotated, email changed, password reset, object archived, object transferred.
- Compare not only status code but also response body, response size, cache headers, timing, side effects, notifications, audit logs, and background jobs.
- For every successful-looking response, verify in the victim-controlled account whether the private state actually changed.
- Prefer proof with your own objects and tenants. If a bug would expose real user data, stop at the first safe indicator and explain the risk without accessing third-party data.


<div style='page-break-after: always;'></div>


## CWE-22 / CWE-35 / CWE-73 — Path Traversal and External Control of File/Path

**Niche:** Download endpoints, import/export, log viewers, file previews, translation files, theme assets, backup retrieval.

**Why this is worth hunting:** HackerOne snippets show path traversal-related CWEs. Manual testing shines because you identify file-path parameters hidden behind business features.

### Unauthenticated angle

Look for `file`, `path`, `template`, `locale`, `theme`, `download`, `attachment`, `key`, `name`, `url`, `backup` parameters in public endpoints.

### Authenticated angle

Test file downloads, report exports, generated PDFs, attachments, support ticket files, project imports, archive extraction, and admin logs using files you own.

### Manual testing workflow

1. First prove you can access your own file by ID/path.
2. Attempt path normalization variations against a harmless known file or your own uploaded file location; do not read sensitive system files unless explicitly permitted.
3. Test encoded traversal, mixed separators, dot-dot segments, null-byte-like truncation in legacy systems, Windows paths, zip paths, and object storage keys.
4. Test tenant boundary: can you download another account's file by changing path/key?
5. Test archive extraction: upload a zip with harmless nested paths and verify whether files escape intended directory only in a sandboxed account if allowed.
6. For impact, show unauthorized access to your other test account's file or controlled harmless file outside expected directory.


### What makes the report strong

Arbitrary file read, cross-tenant file read, overwrite, config exposure, source exposure.

### What usually becomes informative or rejected

Do not access `/etc/passwd`, cloud credentials, or sensitive server files unless the program explicitly allows such proof. Prefer controlled files.

### Useful tools

Burp, curl, custom test archives, zipinfo, safe wordlists.

### Extra manual heuristics

- Look for the same operation exposed through more than one route. Modern apps often have REST, GraphQL, mobile, admin, and internal-feeling routes for the same action.
- Try the bug after state changes: user removed, role downgraded, subscription expired, invitation revoked, token rotated, email changed, password reset, object archived, object transferred.
- Compare not only status code but also response body, response size, cache headers, timing, side effects, notifications, audit logs, and background jobs.
- For every successful-looking response, verify in the victim-controlled account whether the private state actually changed.
- Prefer proof with your own objects and tenants. If a bug would expose real user data, stop at the first safe indicator and explain the risk without accessing third-party data.


<div style='page-break-after: always;'></div>


## CWE-434 — Unrestricted Upload of File with Dangerous Type

**Niche:** Avatar upload, file preview, importers, support attachments, theme/plugin uploads, SVG/HTML/PDF preview, public object storage.

**Why this is worth hunting:** Upload bugs become valuable when they cross from simple extension bypass to executable content, stored XSS, malware scanning bypass, SSRF via parser, or cross-tenant file access.

### Unauthenticated angle

Public uploads are uncommon but include contact forms, application forms, profile images, and public file sharing.

### Authenticated angle

Test every upload context with harmless files: avatar, org logo, documents, CSV import, PDF invoice, markdown, HTML export, SVG image, zip import.

### Manual testing workflow

1. Map validation points: client-side, server-side extension, MIME type, magic bytes, content scanning, storage domain, rendering domain.
2. Upload harmless test files with mismatched extension/MIME and observe behavior.
3. Test SVG script execution only in your controlled account and browser.
4. Test HTML served from same origin vs separate static origin.
5. Test public accessibility and authorization of uploaded files.
6. Test filename injection into headers, logs, HTML, and emails.
7. Test archive import with benign files for path traversal, zip bombs only conceptually; do not upload resource-exhaustion payloads.


### What makes the report strong

Stored XSS, same-origin script execution, unauthorized file read, malware distribution risk, parser SSRF, server-side file write in rare cases.

### What usually becomes informative or rejected

Extension bypass alone is weak unless the file is executed, rendered dangerously, or accessible in a sensitive context.

### Useful tools

Burp, file command, exiftool, SVG/HTML harmless canaries, browser DevTools.

### Extra manual heuristics

- Look for the same operation exposed through more than one route. Modern apps often have REST, GraphQL, mobile, admin, and internal-feeling routes for the same action.
- Try the bug after state changes: user removed, role downgraded, subscription expired, invitation revoked, token rotated, email changed, password reset, object archived, object transferred.
- Compare not only status code but also response body, response size, cache headers, timing, side effects, notifications, audit logs, and background jobs.
- For every successful-looking response, verify in the victim-controlled account whether the private state actually changed.
- Prefer proof with your own objects and tenants. If a bug would expose real user data, stop at the first safe indicator and explain the risk without accessing third-party data.


<div style='page-break-after: always;'></div>


## CWE-20 — Improper Input Validation

**Niche:** Business logic values, negative numbers, scientific notation, array/object confusion, duplicate parameters, unexpected content types.

**Why this is worth hunting:** HackerOne snippets show this category in top lists. It is broad, so target places where bad input changes money, permissions, quotas, identity, or workflow.

### Unauthenticated angle

Signup, invitation, search, public forms, coupon redemption, public API filters, file imports.

### Authenticated angle

Pricing, checkout, quantity, credits, quotas, role arrays, permissions, plan IDs, account limits, webhooks, notification preferences.

### Manual testing workflow

1. Find parameters with business meaning: price, quantity, role, status, owner, plan, trial, quota, limit, discount, currency, verified, approved.
2. Try boundary values safely: 0, -1, 1.5, large but non-harmful numbers, empty string, null, false, arrays instead of strings, objects instead of IDs.
3. Test duplicate parameters: first wins vs last wins vs array merge.
4. Test content type changes: JSON to form, form to multipart, GraphQL variables vs query string.
5. Test server recalculation: price and role must be server-side, not trusted from client.
6. Test workflow state: can you submit final state without valid prior steps?


### What makes the report strong

Payment bypass, quota bypass, role manipulation, workflow bypass, data corruption, unauthorized state transitions.

### What usually becomes informative or rejected

Generic 500 errors without impact are often low or out of scope. Do not crash services repeatedly.

### Useful tools

Burp Repeater, Param Miner, jq, Postman, small boundary-value checklist.

### Extra manual heuristics

- Look for the same operation exposed through more than one route. Modern apps often have REST, GraphQL, mobile, admin, and internal-feeling routes for the same action.
- Try the bug after state changes: user removed, role downgraded, subscription expired, invitation revoked, token rotated, email changed, password reset, object archived, object transferred.
- Compare not only status code but also response body, response size, cache headers, timing, side effects, notifications, audit logs, and background jobs.
- For every successful-looking response, verify in the victim-controlled account whether the private state actually changed.
- Prefer proof with your own objects and tenants. If a bug would expose real user data, stop at the first safe indicator and explain the risk without accessing third-party data.


<div style='page-break-after: always;'></div>


## CWE-400 — Uncontrolled Resource Consumption

**Niche:** Expensive exports, PDF generation, image transforms, search, report builders, webhook retries, email/SMS sends, AI features, bulk imports.

**Why this is worth hunting:** HackerOne snippets show resource consumption as common. In bug bounty, it is tricky because DoS is often out of scope; focus on business-cost or quota bypass with safe proof.

### Unauthenticated angle

Public search, signup email sends, password reset email sends, contact form attachments, public PDF rendering. Keep testing minimal.

### Authenticated angle

Export jobs, imports, reports, AI generation, image processing, webhook retries, invitation emails, build/deploy triggers.

### Manual testing workflow

1. Read program policy for DoS/resource tests before touching this class.
2. Use tiny controlled tests: two or three requests only, no stress testing.
3. Look for missing per-account quotas rather than proving capacity exhaustion.
4. Check whether expensive actions can be triggered without payment or after trial expiration.
5. Check whether the same job can be queued repeatedly by replaying idempotency-sensitive requests.
6. Check whether the endpoint sends third-party paid resources: SMS, email, AI tokens, build minutes, file conversions.
7. Report the missing control and theoretical amplification; do not perform amplification.


### What makes the report strong

Financial cost, abuse of paid resources, queue flooding risk, rate-limit bypass on expensive workflows.

### What usually becomes informative or rejected

Do not demonstrate real DoS. A theoretical expensive endpoint may be informative unless there is a clear abuse path.

### Useful tools

Burp, manual replay, quota observation, account billing/trial state checks.

### Extra manual heuristics

- Look for the same operation exposed through more than one route. Modern apps often have REST, GraphQL, mobile, admin, and internal-feeling routes for the same action.
- Try the bug after state changes: user removed, role downgraded, subscription expired, invitation revoked, token rotated, email changed, password reset, object archived, object transferred.
- Compare not only status code but also response body, response size, cache headers, timing, side effects, notifications, audit logs, and background jobs.
- For every successful-looking response, verify in the victim-controlled account whether the private state actually changed.
- Prefer proof with your own objects and tenants. If a bug would expose real user data, stop at the first safe indicator and explain the risk without accessing third-party data.


<div style='page-break-after: always;'></div>


## CWE-798 / CWE-321 — Hard-coded Credentials / Hard-coded Cryptographic Key

**Niche:** Mobile apps, JS bundles, public repos, SDKs, sample configs, Docker images, leaked `.env`, client-side API keys with excessive privileges.

**Why this is worth hunting:** HackerOne snippets include hard-coded credentials and keys. The niche is proving the key has unauthorized capability, not merely that a string looks secret.

### Unauthenticated angle

Inspect public JS, mobile APKs where in scope, public repos, package registries, Docker images, documentation, source maps, browser storage.

### Authenticated angle

Check whether authenticated pages reveal tenant-specific tokens, integration secrets, webhook signing secrets, API keys, cloud storage credentials, map/payment/provider keys with dangerous scopes.

### Manual testing workflow

1. Identify candidate secret and its context.
2. Determine whether it is intentionally public, publishable, test-only, or restricted by domain/IP/scope.
3. Use provider documentation to understand what the key can do; do not abuse it.
4. Validate safely with a minimal metadata or whoami-style request if permitted.
5. For signing keys, show that exposure could forge tokens only if safe and against your own account/lab; otherwise explain cryptographic impact.
6. Search for surrounding config: environment, project, scopes, endpoints, tenant IDs, bucket names.
7. Report with exact location, scope, capability, and remediation.


### What makes the report strong

Unauthorized API access, cloud resource access, token forgery, signing bypass, data exposure, account takeover through integration.

### What usually becomes informative or rejected

Public analytics keys, map tile keys, or client-side SDK keys may be informative unless unrestricted or overprivileged.

### Useful tools

DevTools, source-map review, trufflehog/gitleaks on in-scope repos, apktool/jadx where permitted, provider CLI read-only validation.

### Extra manual heuristics

- Look for the same operation exposed through more than one route. Modern apps often have REST, GraphQL, mobile, admin, and internal-feeling routes for the same action.
- Try the bug after state changes: user removed, role downgraded, subscription expired, invitation revoked, token rotated, email changed, password reset, object archived, object transferred.
- Compare not only status code but also response body, response size, cache headers, timing, side effects, notifications, audit logs, and background jobs.
- For every successful-looking response, verify in the victim-controlled account whether the private state actually changed.
- Prefer proof with your own objects and tenants. If a bug would expose real user data, stop at the first safe indicator and explain the risk without accessing third-party data.


<div style='page-break-after: always;'></div>


## CWE-312 / CWE-522 / CWE-922 / CWE-532 — Sensitive Data Storage and Logging

**Niche:** Secrets in logs, client storage, exports, backups, debug endpoints, mobile local storage, downloadable reports.

**Why this is worth hunting:** HackerOne snippets include cleartext storage, insecure storage, and log exposure. The key is proving sensitive data exposure across trust boundaries.

### Unauthenticated angle

Look for public debug logs, exposed backups, public object storage, `.env`, `.git`, source maps with secrets, public crash reports.

### Authenticated angle

Check exports, audit logs, webhook logs, integration logs, support bundles, browser localStorage, mobile storage, downloadable reports, CSV/PDF invoices.

### Manual testing workflow

1. Identify sensitive material: session tokens, reset tokens, API keys, OAuth codes, passwords, secrets, PII, private messages, payment details.
2. Check if data is accessible to unauthorized roles or after revocation.
3. Search controlled test secrets you entered into forms and see where they reappear.
4. Check webhook delivery logs for Authorization headers and payload secrets.
5. Check browser storage after logout and after account switch.
6. Check downloadable exports for hidden columns or other users' data.
7. Prove exposure with your own secrets or test data, not real user secrets.


### What makes the report strong

Credential disclosure, token replay, PII exposure, compliance-sensitive leak, cross-tenant leak.

### What usually becomes informative or rejected

Masked tokens, last four characters, or intentionally visible own API keys are usually not bugs.

### Useful tools

DevTools, export review, grep, jq, CSV tools, Burp search, storage inspection.

### Extra manual heuristics

- Look for the same operation exposed through more than one route. Modern apps often have REST, GraphQL, mobile, admin, and internal-feeling routes for the same action.
- Try the bug after state changes: user removed, role downgraded, subscription expired, invitation revoked, token rotated, email changed, password reset, object archived, object transferred.
- Compare not only status code but also response body, response size, cache headers, timing, side effects, notifications, audit logs, and background jobs.
- For every successful-looking response, verify in the victim-controlled account whether the private state actually changed.
- Prefer proof with your own objects and tenants. If a bug would expose real user data, stop at the first safe indicator and explain the risk without accessing third-party data.


<div style='page-break-after: always;'></div>


## CWE-200 / CWE-201 / CWE-359 — Information Exposure and Privacy Violation

**Niche:** Private data in APIs, overbroad GraphQL queries, hidden fields, error responses, search indexing, object metadata, response-after-redirect leaks.

**Why this is worth hunting:** Info exposure is common but often informative. The niche is private, sensitive, cross-boundary data that the user is not authorized to see.

### Unauthenticated angle

Public profiles, search APIs, share links, cached pages, unauthenticated API responses, robots/sitemaps, public object metadata.

### Authenticated angle

Cross-user data in list endpoints, hidden fields in JSON, GraphQL fragments, exports, audit logs, notifications, admin-only metadata returned to members.

### Manual testing workflow

1. Compare Account A and Account B responses for the same endpoint.
2. Look for fields hidden by UI but returned in API: email, phone, internal ID, role, plan, tokens, private flags, billing metadata.
3. Check pagination and filters for records outside your tenant.
4. Check response bodies on 302/403/404 responses.
5. Check verbose errors by causing harmless validation failures.
6. Check GraphQL queries for overfetching by adding fields already present in schema only where introspection/use is allowed.
7. Tie data to confidentiality impact.


### What makes the report strong

PII exposure, private business data exposure, tokens/secrets, tenant/user enumeration with meaningful abuse, internal metadata that enables further attack.

### What usually becomes informative or rejected

Public usernames, public IDs, generic stack traces without secrets, and harmless version strings are usually low.

### Useful tools

Burp Comparer, jq, GraphQL clients, DevTools, search cache checks.

### Extra manual heuristics

- Look for the same operation exposed through more than one route. Modern apps often have REST, GraphQL, mobile, admin, and internal-feeling routes for the same action.
- Try the bug after state changes: user removed, role downgraded, subscription expired, invitation revoked, token rotated, email changed, password reset, object archived, object transferred.
- Compare not only status code but also response body, response size, cache headers, timing, side effects, notifications, audit logs, and background jobs.
- For every successful-looking response, verify in the victim-controlled account whether the private state actually changed.
- Prefer proof with your own objects and tenants. If a bug would expose real user data, stop at the first safe indicator and explain the risk without accessing third-party data.


<div style='page-break-after: always;'></div>


## CWE-345 / CWE-346 — Insufficient Verification of Data Authenticity / Origin Validation

**Niche:** Webhooks, callbacks, postMessage, CORS, SAML/OIDC metadata, inbound email, signed URLs, mobile deep links.

**Why this is worth hunting:** These are niche manual wins because they involve trust boundaries between systems, not obvious injection points.

### Unauthenticated angle

Test public callback endpoints, webhook receivers, link previews, inbound email handlers, unauthenticated signed URL endpoints.

### Authenticated angle

Configure your own webhook/integration and inspect signature verification, replay protection, origin checks, and tenant binding.

### Manual testing workflow

1. Identify the trust claim: signature, origin header, referer, token, domain allowlist, tenant ID, callback URL, timestamp.
2. Remove or alter the signature/header and check if the action still succeeds.
3. Replay an old signed request and check for nonce/timestamp enforcement.
4. Change tenant/resource identifiers inside a signed or callback payload.
5. Test CORS only where credentials and private data are involved; `Access-Control-Allow-Origin: *` alone is not always a bug.
6. Test postMessage handlers for origin validation and message schema validation using a local page against your own account.
7. For SAML/OIDC, check metadata and issuer/audience binding with your own test IdP where allowed.


### What makes the report strong

Forged webhook events, cross-origin data read, account linking confusion, callback takeover, tenant boundary bypass.

### What usually becomes informative or rejected

Do not spoof third-party services in ways that affect real users or external companies. Use your own integration endpoints.

### Useful tools

Burp, local test page, webhook receiver, JWT/SAML inspection tools, browser console.

### Extra manual heuristics

- Look for the same operation exposed through more than one route. Modern apps often have REST, GraphQL, mobile, admin, and internal-feeling routes for the same action.
- Try the bug after state changes: user removed, role downgraded, subscription expired, invitation revoked, token rotated, email changed, password reset, object archived, object transferred.
- Compare not only status code but also response body, response size, cache headers, timing, side effects, notifications, audit logs, and background jobs.
- For every successful-looking response, verify in the victim-controlled account whether the private state actually changed.
- Prefer proof with your own objects and tenants. If a bug would expose real user data, stop at the first safe indicator and explain the risk without accessing third-party data.


<div style='page-break-after: always;'></div>


## CWE-610 / CWE-829 / CWE-494 — Externally Controlled Resource / Untrusted Control Sphere / Code Download Without Integrity

**Niche:** Script URLs, plugin/theme repositories, update channels, import URLs, package registries, remote templates.

**Why this is worth hunting:** HackerOne snippets include external resource references. These are under-hunted because they sit between appsec and supply-chain testing.

### Unauthenticated angle

Look at public HTML/JS for external scripts without integrity, dependency URLs, update metadata, plugin feeds, remote templates.

### Authenticated angle

Test admin-configurable URLs, webhooks, custom branding assets, remote templates, documentation importers, package or repository integrations.

### Manual testing workflow

1. Identify resources fetched or executed from outside the target-controlled trust boundary.
2. Check whether a user can control the resource URL or domain.
3. Check whether integrity checks, signature verification, allowlists, and content-type restrictions exist.
4. Check whether tenant A can influence tenant B's loaded resource.
5. For proof, use harmless controlled content and show where it is loaded/executed/rendered.
6. Do not attempt supply-chain compromise; demonstrate missing verification in a controlled path.


### What makes the report strong

Script injection, template takeover, plugin/update compromise, cross-tenant content injection.

### What usually becomes informative or rejected

Third-party scripts intentionally used by marketing pages may be accepted risk unless you can control them or show compromise path.

### Useful tools

DevTools, Subresource Integrity checks, Burp, DNS/HTTP logs, controlled resource server.

### Extra manual heuristics

- Look for the same operation exposed through more than one route. Modern apps often have REST, GraphQL, mobile, admin, and internal-feeling routes for the same action.
- Try the bug after state changes: user removed, role downgraded, subscription expired, invitation revoked, token rotated, email changed, password reset, object archived, object transferred.
- Compare not only status code but also response body, response size, cache headers, timing, side effects, notifications, audit logs, and background jobs.
- For every successful-looking response, verify in the victim-controlled account whether the private state actually changed.
- Prefer proof with your own objects and tenants. If a bug would expose real user data, stop at the first safe indicator and explain the risk without accessing third-party data.


<div style='page-break-after: always;'></div>


## CWE-502 — Deserialization of Untrusted Data

**Niche:** Signed/encrypted-looking state blobs, Java/PHP/Ruby/Python serialized cookies, import files, queue messages, ViewState, JWT-like custom tokens.

**Why this is worth hunting:** HackerOne snippets include deserialization. It can be high impact, but safe bounty testing must avoid weaponized gadget chains.

### Unauthenticated angle

Look for serialized objects in cookies, hidden fields, URL parameters, upload/import formats, remember-me tokens.

### Authenticated angle

Test import/export features, workflow state tokens, draft objects, preferences, cart state, SSO RelayState-like blobs.

### Manual testing workflow

1. Identify serialization markers: Java `rO0`, PHP `O:`, Python pickle signatures, .NET ViewState, Ruby Marshal, custom base64 JSON with signatures.
2. Decode safely and inspect structure; do not run untrusted deserialization tools against the target.
3. Change benign fields and check whether signature/integrity verification catches tampering.
4. Check whether object type/class names are accepted from user input.
5. Check whether import files can alter unauthorized fields.
6. For proof, demonstrate safe integrity bypass or unauthorized field change, not remote code execution payloads.


### What makes the report strong

Tampering, privilege changes, server-side object injection risk, sometimes code execution if responsibly validated in lab/source context.

### What usually becomes informative or rejected

Do not fire public exploit gadget payloads at live targets unless explicitly permitted. Do not crash services.

### Useful tools

Burp Decoder, CyberChef, language-specific offline decoders, ysoserial only in labs or explicitly authorized tests.

### Extra manual heuristics

- Look for the same operation exposed through more than one route. Modern apps often have REST, GraphQL, mobile, admin, and internal-feeling routes for the same action.
- Try the bug after state changes: user removed, role downgraded, subscription expired, invitation revoked, token rotated, email changed, password reset, object archived, object transferred.
- Compare not only status code but also response body, response size, cache headers, timing, side effects, notifications, audit logs, and background jobs.
- For every successful-looking response, verify in the victim-controlled account whether the private state actually changed.
- Prefer proof with your own objects and tenants. If a bug would expose real user data, stop at the first safe indicator and explain the risk without accessing third-party data.


<div style='page-break-after: always;'></div>


## CWE-611 — XML External Entity

**Niche:** SAML, SVG, DOCX/XLSX/PDF conversion, XML APIs, SOAP, RSS/Atom import, upload parsers.

**Why this is worth hunting:** XXE is less common now but still niche in enterprise and file-processing features. It often overlaps SSRF and file disclosure.

### Unauthenticated angle

Public XML upload/import endpoints, feed importers, SVG upload, metadata parsers.

### Authenticated angle

SAML metadata upload, enterprise integrations, document conversion, invoice XML import, product feed ingestion.

### Manual testing workflow

1. Confirm XML is accepted and parsed server-side.
2. Use a harmless external entity pointing to your controlled callback domain if permitted.
3. Test whether DTDs are disabled and whether external entities are resolved.
4. Avoid reading local files or internal resources unless explicitly allowed.
5. Check blind behavior via collaborator logs.
6. Check whether parser errors include sensitive file paths or content.
7. Report safe callback proof plus reachable impact.


### What makes the report strong

SSRF, file read, sensitive parser error exposure, internal network reachability.

### What usually becomes informative or rejected

Do not retrieve server files or metadata endpoints without permission.

### Useful tools

Burp Collaborator/Interactsh, controlled XML files, SAML test metadata.

### Extra manual heuristics

- Look for the same operation exposed through more than one route. Modern apps often have REST, GraphQL, mobile, admin, and internal-feeling routes for the same action.
- Try the bug after state changes: user removed, role downgraded, subscription expired, invitation revoked, token rotated, email changed, password reset, object archived, object transferred.
- Compare not only status code but also response body, response size, cache headers, timing, side effects, notifications, audit logs, and background jobs.
- For every successful-looking response, verify in the victim-controlled account whether the private state actually changed.
- Prefer proof with your own objects and tenants. If a bug would expose real user data, stop at the first safe indicator and explain the risk without accessing third-party data.


<div style='page-break-after: always;'></div>


## CWE-295 — Improper Certificate Validation

**Niche:** Mobile apps, desktop clients, webhooks to HTTPS endpoints, integrations, package/update fetchers, SSO metadata fetch.

**Why this is worth hunting:** HackerOne discovery has a CWE-295 page. It is especially valuable when a client accepts invalid TLS for sensitive traffic.

### Unauthenticated angle

Usually not applicable for pure web apps except public clients or downloadable apps.

### Authenticated angle

Test mobile/desktop apps and integrations where you can configure endpoints. Check whether TLS validation is enforced.

### Manual testing workflow

1. Use your own test endpoint with a deliberately invalid certificate in a controlled environment.
2. Check whether the app refuses connection as expected.
3. For mobile apps, proxy only your own device/account and respect program rules.
4. Check whether certificate pinning exists and whether bypass testing is allowed; many programs restrict mobile reverse engineering.
5. For webhooks, configure HTTPS endpoint with invalid cert and see if the service posts secrets anyway.
6. Report only when sensitive data or auth-bearing traffic is exposed to MITM risk.


### What makes the report strong

MITM of sensitive client traffic, webhook secret exposure, update/package tampering.

### What usually becomes informative or rejected

Generic TLS scanner output on the website is not the same as CWE-295 in an application client.

### Useful tools

mitmproxy/Burp for own device, test HTTPS server, self-signed cert, mobile proxy setup where allowed.

### Extra manual heuristics

- Look for the same operation exposed through more than one route. Modern apps often have REST, GraphQL, mobile, admin, and internal-feeling routes for the same action.
- Try the bug after state changes: user removed, role downgraded, subscription expired, invitation revoked, token rotated, email changed, password reset, object archived, object transferred.
- Compare not only status code but also response body, response size, cache headers, timing, side effects, notifications, audit logs, and background jobs.
- For every successful-looking response, verify in the victim-controlled account whether the private state actually changed.
- Prefer proof with your own objects and tenants. If a bug would expose real user data, stop at the first safe indicator and explain the risk without accessing third-party data.


<div style='page-break-after: always;'></div>


## CWE-915 — Improperly Controlled Modification of Dynamically-Determined Object Attributes / Mass Assignment

**Niche:** JSON APIs accepting hidden fields: role, plan, verified, owner, balance, permissions, organization_id.

**Why this is worth hunting:** Mass assignment is a classic manual API bug and maps closely to OWASP API object property authorization.

### Unauthenticated angle

Signup and onboarding forms sometimes allow hidden properties: role, plan, email_verified, trial_days, referral_credit.

### Authenticated angle

Profile update, org settings, user update, invite creation, project update, billing settings, API object creation.

### Manual testing workflow

1. Observe a create/update JSON request.
2. Add likely server-side fields from response into the update request.
3. Try `role`, `isAdmin`, `admin`, `owner`, `plan`, `status`, `verified`, `permissions`, `scopes`, `balance`, `quota`, `organizationId`.
4. Test nested objects and arrays: `user[role]`, `permissions[]`, GraphQL input objects.
5. Confirm server-side state changed by reloading the object or reading from another account.
6. Test whether lower roles can assign higher roles to themselves or others.


### What makes the report strong

Privilege escalation, plan/quota bypass, account verification bypass, ownership transfer.

### What usually becomes informative or rejected

Adding a field that is ignored is not a bug. Changing cosmetic fields is low.

### Useful tools

Burp, jq, response-to-request field diffing, Postman.

### Extra manual heuristics

- Look for the same operation exposed through more than one route. Modern apps often have REST, GraphQL, mobile, admin, and internal-feeling routes for the same action.
- Try the bug after state changes: user removed, role downgraded, subscription expired, invitation revoked, token rotated, email changed, password reset, object archived, object transferred.
- Compare not only status code but also response body, response size, cache headers, timing, side effects, notifications, audit logs, and background jobs.
- For every successful-looking response, verify in the victim-controlled account whether the private state actually changed.
- Prefer proof with your own objects and tenants. If a bug would expose real user data, stop at the first safe indicator and explain the risk without accessing third-party data.


<div style='page-break-after: always;'></div>


## CWE-367 — Time-of-check Time-of-use Race Condition

**Niche:** Coupons, payments, withdrawals, invites, password reset, email verification, file permissions, limited resources.

**Why this is worth hunting:** HackerOne has a CWE-367 discovery page. Race bugs are niche because they require manual reasoning about state and concurrency.

### Unauthenticated angle

Signup, email verification, limited-code redemption, public inventory/reservation flows.

### Authenticated angle

Balance transfer, coupon use, gift card redemption, plan upgrade/downgrade, invite acceptance, role changes, token rotation, file share revoke.

### Manual testing workflow

1. Identify a single-use or limited-use action.
2. Send two nearly simultaneous requests against your own resource using Burp Repeater group send or Turbo Intruder with tiny counts.
3. Keep the test minimal and harmless; do not stress systems.
4. Check if both requests succeed when only one should.
5. Test approval/revocation races: use token while revoking, download while permission changes, redeem while deleting.
6. Document state before, concurrent actions, state after, and business impact.


### What makes the report strong

Double spend, duplicate coupon use, quota bypass, unauthorized access after revocation, inventory manipulation.

### What usually becomes informative or rejected

High-volume concurrency or DoS is not acceptable. Tiny proof only.

### Useful tools

Burp Repeater group send, Turbo Intruder with safe low count, Caido parallel replay.

### Extra manual heuristics

- Look for the same operation exposed through more than one route. Modern apps often have REST, GraphQL, mobile, admin, and internal-feeling routes for the same action.
- Try the bug after state changes: user removed, role downgraded, subscription expired, invitation revoked, token rotated, email changed, password reset, object archived, object transferred.
- Compare not only status code but also response body, response size, cache headers, timing, side effects, notifications, audit logs, and background jobs.
- For every successful-looking response, verify in the victim-controlled account whether the private state actually changed.
- Prefer proof with your own objects and tenants. If a bug would expose real user data, stop at the first safe indicator and explain the risk without accessing third-party data.


<div style='page-break-after: always;'></div>


## CWE-441 — Confused Deputy

**Niche:** OAuth app permissions, integrations acting with broader privileges, webhook-triggered actions, importers using service accounts.

**Why this is worth hunting:** HackerOne has a CWE-441 discovery page. These bugs are under-hunted because they require understanding who is acting on whose behalf.

### Unauthenticated angle

Public integrations that trigger privileged backend actions, link previews that use privileged network position.

### Authenticated angle

OAuth app connected by low-privileged user but acting as org admin; webhook from tenant A triggering tenant B; import job using global service account.

### Manual testing workflow

1. Identify the deputy: service account, integration bot, webhook processor, import worker, preview server, OAuth app.
2. Identify whose authority it should use.
3. Create action as low-privileged user and observe whether the deputy performs admin-level action.
4. Change tenant/resource IDs in integration payloads.
5. Check whether webhook or callback includes signed tenant binding.
6. Prove with your own tenants/accounts only.


### What makes the report strong

Privilege escalation through trusted service, cross-tenant action, unauthorized integration changes.

### What usually becomes informative or rejected

Do not involve real third-party tenants or production integrations beyond your own controlled accounts.

### Useful tools

Webhook logs, Burp, integration sandbox, OAuth test apps.

### Extra manual heuristics

- Look for the same operation exposed through more than one route. Modern apps often have REST, GraphQL, mobile, admin, and internal-feeling routes for the same action.
- Try the bug after state changes: user removed, role downgraded, subscription expired, invitation revoked, token rotated, email changed, password reset, object archived, object transferred.
- Compare not only status code but also response body, response size, cache headers, timing, side effects, notifications, audit logs, and background jobs.
- For every successful-looking response, verify in the victim-controlled account whether the private state actually changed.
- Prefer proof with your own objects and tenants. If a bug would expose real user data, stop at the first safe indicator and explain the risk without accessing third-party data.


<div style='page-break-after: always;'></div>


## CWE-269 / CWE-250 — Improper Privilege Management / Execution with Unnecessary Privileges

**Niche:** Admin-only endpoints reachable by lower roles, support impersonation, service tokens over-scoped, API keys with excessive scopes.

**Why this is worth hunting:** HackerOne snippets include CWE-250 and authorization-adjacent categories. High-impact bugs often come from overly broad service powers.

### Unauthenticated angle

Public admin functions are rare but check exposed admin panels, setup routes, debug consoles, and install wizards only in scope.

### Authenticated angle

Test owner/member/guest separation, API scopes, integration tokens, support tools, org switching, tenant admin APIs.

### Manual testing workflow

1. Create a least-privileged account and capture all accessible endpoints.
2. Discover admin endpoints from JS/UI/docs and call them as lower role.
3. Inspect API key scopes and try safe read/write actions outside scope.
4. Check whether role changes require re-login or re-tokenization.
5. Check if support/impersonation links leak or are reusable.
6. Check if org-level admin token works across orgs.


### What makes the report strong

Privilege escalation, over-scoped token, admin action as low user, tenant compromise.

### What usually becomes informative or rejected

UI access to an admin page that fails server-side is not enough unless sensitive data leaks.

### Useful tools

Burp, role matrix, token scope diffing, API docs.

### Extra manual heuristics

- Look for the same operation exposed through more than one route. Modern apps often have REST, GraphQL, mobile, admin, and internal-feeling routes for the same action.
- Try the bug after state changes: user removed, role downgraded, subscription expired, invitation revoked, token rotated, email changed, password reset, object archived, object transferred.
- Compare not only status code but also response body, response size, cache headers, timing, side effects, notifications, audit logs, and background jobs.
- For every successful-looking response, verify in the victim-controlled account whether the private state actually changed.
- Prefer proof with your own objects and tenants. If a bug would expose real user data, stop at the first safe indicator and explain the risk without accessing third-party data.


<div style='page-break-after: always;'></div>


## CWE-770 / CWE-772 / CWE-835 — Resource Allocation, Missing Release, Infinite Loops

**Niche:** Import loops, recursive parsers, webhook retry storms, search queries, regex-heavy endpoints, AI prompt workflows.

**Why this is worth hunting:** HackerOne snippets include CWE-835. Most programs restrict DoS; the niche is safely demonstrating a missing guard on your own resource.

### Unauthenticated angle

Avoid unless explicitly allowed. Public endpoints can be sensitive to DoS policies.

### Authenticated angle

Use a small harmless input that proves unbounded behavior through response time or queue creation without stressing the system.

### Manual testing workflow

1. Read policy before testing.
2. Choose one controlled resource and one tiny payload.
3. Look for missing max depth, max file count, max recursion, max regex time, max rows, max pages.
4. Observe behavior once or twice; do not repeatedly trigger expensive processing.
5. Prefer logic proof: the app accepts configuration that would cause unbounded recursion, without executing it at scale.
6. Frame the report as missing limits and include conservative reproduction.


### What makes the report strong

Cost amplification, queue exhaustion risk, service degradation risk, account-level abuse.

### What usually becomes informative or rejected

Do not crash, stress, or benchmark production systems.

### Useful tools

Burp, small controlled files, timing observation, job queue UI.

### Extra manual heuristics

- Look for the same operation exposed through more than one route. Modern apps often have REST, GraphQL, mobile, admin, and internal-feeling routes for the same action.
- Try the bug after state changes: user removed, role downgraded, subscription expired, invitation revoked, token rotated, email changed, password reset, object archived, object transferred.
- Compare not only status code but also response body, response size, cache headers, timing, side effects, notifications, audit logs, and background jobs.
- For every successful-looking response, verify in the victim-controlled account whether the private state actually changed.
- Prefer proof with your own objects and tenants. If a bug would expose real user data, stop at the first safe indicator and explain the risk without accessing third-party data.


<div style='page-break-after: always;'></div>


## CWE-347 / CWE-347-adjacent — Improper Verification of Cryptographic Signature

**Niche:** JWT, signed URLs, webhook signatures, SAML assertions, license tokens, password reset tokens.

**Why this is worth hunting:** Cryptographic verification mistakes are less frequent but high signal because impact is often direct privilege or identity forgery.

### Unauthenticated angle

Signed unsubscribe links, reset tokens, invite tokens, public signed downloads, license verification endpoints.

### Authenticated angle

JWT claims, webhook signatures, signed SSO payloads, signed file URLs, API request signatures.

### Manual testing workflow

1. Decode tokens and identify claims and signature algorithm.
2. Change a harmless claim and verify whether signature failure blocks it.
3. Check algorithm confusion only safely: `none`, HS/RS confusion concepts, `kid` path/URL injection should be tested without harmful file reads.
4. Check expiry, audience, issuer, tenant, subject, and nonce binding.
5. Check signed URLs for object/tenant swapping and expiry enforcement.
6. Check webhook signatures for replay and body canonicalization bugs.


### What makes the report strong

Authentication bypass, privilege escalation, signed URL bypass, forged webhook events.

### What usually becomes informative or rejected

Do not brute force weak JWT secrets unless explicitly allowed. Do not forge access to real users.

### Useful tools

jwt_tool, jose, Burp Decoder, SAML-tracer, webhook signing scripts.

### Extra manual heuristics

- Look for the same operation exposed through more than one route. Modern apps often have REST, GraphQL, mobile, admin, and internal-feeling routes for the same action.
- Try the bug after state changes: user removed, role downgraded, subscription expired, invitation revoked, token rotated, email changed, password reset, object archived, object transferred.
- Compare not only status code but also response body, response size, cache headers, timing, side effects, notifications, audit logs, and background jobs.
- For every successful-looking response, verify in the victim-controlled account whether the private state actually changed.
- Prefer proof with your own objects and tenants. If a bug would expose real user data, stop at the first safe indicator and explain the risk without accessing third-party data.


<div style='page-break-after: always;'></div>


## CWE-521 / CWE-1391 / CWE-1392 / CWE-1393 — Weak Password Requirements and Default Credentials

**Niche:** Default admin/setup accounts, initial install routes, device dashboards, weak recovery/bootstrap passwords.

**Why this is worth hunting:** HackerOne snippets include default/weak credential related CWEs. Many reports are invalid unless the account is live, in scope, and impactful.

### Unauthenticated angle

Check setup pages, default installation pages, public admin consoles, vendor appliances in scope. Do not attempt credential stuffing.

### Authenticated angle

Check organization-created default passwords, temporary passwords, invite passwords, generated recovery codes, API tokens shown once but reusable forever.

### Manual testing workflow

1. Read program rules for credential testing.
2. Try only documented default credentials if explicitly allowed or if the target is your own created instance.
3. Check if setup wizard remains enabled after installation.
4. Check if temporary invite passwords expire and force change.
5. Check password policy only where weak password acceptance leads to meaningful account/security risk.
6. Report exposed default creds with exact asset, scope proof, and minimal safe access.


### What makes the report strong

Administrative access, takeover of deployed instance, weak bootstrap chain, compliance risk.

### What usually becomes informative or rejected

Do not spray passwords. Weak password policy alone is often informative unless policy says otherwise.

### Useful tools

Browser, vendor docs, program scope notes, no brute force.

### Extra manual heuristics

- Look for the same operation exposed through more than one route. Modern apps often have REST, GraphQL, mobile, admin, and internal-feeling routes for the same action.
- Try the bug after state changes: user removed, role downgraded, subscription expired, invitation revoked, token rotated, email changed, password reset, object archived, object transferred.
- Compare not only status code but also response body, response size, cache headers, timing, side effects, notifications, audit logs, and background jobs.
- For every successful-looking response, verify in the victim-controlled account whether the private state actually changed.
- Prefer proof with your own objects and tenants. If a bug would expose real user data, stop at the first safe indicator and explain the risk without accessing third-party data.


<div style='page-break-after: always;'></div>


## CVE Discovery Playbook — Safe CVE hunting philosophy

CVE discovery should not become public-exploit spraying. In bug bounty, a CVE report is strongest when you prove: the asset is in scope, the product/version is affected, the vulnerable component is reachable, the vendor advisory maps to the deployed version, the program accepts known-vulnerability reports, and the business impact is realistic. Use CVE discovery as prioritization, not as permission to exploit.


### Manual checklist

- Is the asset explicitly in scope?
- Does the program allow known vulnerability/CVE reports?
- Is the product/component positively identified?
- Is the affected version positively identified?
- Does the advisory say this exact version or range is affected?
- Is the vulnerable feature reachable from the internet or by the tested role?
- Can you validate safely without weaponized exploitation?
- Is there a clear confidentiality, integrity, availability, authentication, authorization, or business impact?
- Have you redacted secrets and avoided third-party data?
- Have you included the fixed version and recommended remediation?

### Safe proof ideas

- Version page, manifest, static asset hash, package metadata, plugin metadata.
- Benign endpoint response that confirms the affected component is loaded.
- Controlled canary callback if the CVE is about outbound fetch behavior and the program allows it.
- Non-mutating request that demonstrates vulnerable routing or parser behavior.
- Vendor advisory comparison showing deployed version is within affected range.
- Screenshot and raw HTTP response headers with sensitive values redacted.


<div style='page-break-after: always;'></div>


## CVE Discovery Playbook — Version exposure and fingerprinting

Start with passive or low-impact techniques: headers, HTML comments, JS bundle paths, static asset hashes, generator meta tags, package lock files, `/version`, `/status`, `/health`, `/api/version`, error pages, documentation, mobile app versions, plugin manifests, changelogs, Docker labels, and public package metadata. Confirm with at least two signals before reporting.


### Manual checklist

- Is the asset explicitly in scope?
- Does the program allow known vulnerability/CVE reports?
- Is the product/component positively identified?
- Is the affected version positively identified?
- Does the advisory say this exact version or range is affected?
- Is the vulnerable feature reachable from the internet or by the tested role?
- Can you validate safely without weaponized exploitation?
- Is there a clear confidentiality, integrity, availability, authentication, authorization, or business impact?
- Have you redacted secrets and avoided third-party data?
- Have you included the fixed version and recommended remediation?

### Safe proof ideas

- Version page, manifest, static asset hash, package metadata, plugin metadata.
- Benign endpoint response that confirms the affected component is loaded.
- Controlled canary callback if the CVE is about outbound fetch behavior and the program allows it.
- Non-mutating request that demonstrates vulnerable routing or parser behavior.
- Vendor advisory comparison showing deployed version is within affected range.
- Screenshot and raw HTTP response headers with sensitive values redacted.


<div style='page-break-after: always;'></div>


## CVE Discovery Playbook — Patch-gap triage

A patch gap exists when the target appears to run a version older than the fixed version. The report must include affected product, observed version, fixed version, advisory link, affected component, asset URL, why the component is reachable, and safe proof. Do not rely on scanner banner alone.


### Manual checklist

- Is the asset explicitly in scope?
- Does the program allow known vulnerability/CVE reports?
- Is the product/component positively identified?
- Is the affected version positively identified?
- Does the advisory say this exact version or range is affected?
- Is the vulnerable feature reachable from the internet or by the tested role?
- Can you validate safely without weaponized exploitation?
- Is there a clear confidentiality, integrity, availability, authentication, authorization, or business impact?
- Have you redacted secrets and avoided third-party data?
- Have you included the fixed version and recommended remediation?

### Safe proof ideas

- Version page, manifest, static asset hash, package metadata, plugin metadata.
- Benign endpoint response that confirms the affected component is loaded.
- Controlled canary callback if the CVE is about outbound fetch behavior and the program allows it.
- Non-mutating request that demonstrates vulnerable routing or parser behavior.
- Vendor advisory comparison showing deployed version is within affected range.
- Screenshot and raw HTTP response headers with sensitive values redacted.


<div style='page-break-after: always;'></div>


## CVE Discovery Playbook — EPSS and prioritization

EPSS estimates the probability of exploitation in the wild over the next 30 days. For hunters, EPSS can help prioritize which CVEs may be worth validating first, but bug bounty payout depends on target exposure, scope, impact, and program policy rather than EPSS alone.


### Manual checklist

- Is the asset explicitly in scope?
- Does the program allow known vulnerability/CVE reports?
- Is the product/component positively identified?
- Is the affected version positively identified?
- Does the advisory say this exact version or range is affected?
- Is the vulnerable feature reachable from the internet or by the tested role?
- Can you validate safely without weaponized exploitation?
- Is there a clear confidentiality, integrity, availability, authentication, authorization, or business impact?
- Have you redacted secrets and avoided third-party data?
- Have you included the fixed version and recommended remediation?

### Safe proof ideas

- Version page, manifest, static asset hash, package metadata, plugin metadata.
- Benign endpoint response that confirms the affected component is loaded.
- Controlled canary callback if the CVE is about outbound fetch behavior and the program allows it.
- Non-mutating request that demonstrates vulnerable routing or parser behavior.
- Vendor advisory comparison showing deployed version is within affected range.
- Screenshot and raw HTTP response headers with sensitive values redacted.


<div style='page-break-after: always;'></div>


## CVE Discovery Playbook — CISA KEV-style thinking

Known exploited vulnerabilities are often valuable for defenders, but bounty programs may reject known issues if they are already tracked, out of scope, or not practically exploitable. Use known-exploited status as context, not proof.


### Manual checklist

- Is the asset explicitly in scope?
- Does the program allow known vulnerability/CVE reports?
- Is the product/component positively identified?
- Is the affected version positively identified?
- Does the advisory say this exact version or range is affected?
- Is the vulnerable feature reachable from the internet or by the tested role?
- Can you validate safely without weaponized exploitation?
- Is there a clear confidentiality, integrity, availability, authentication, authorization, or business impact?
- Have you redacted secrets and avoided third-party data?
- Have you included the fixed version and recommended remediation?

### Safe proof ideas

- Version page, manifest, static asset hash, package metadata, plugin metadata.
- Benign endpoint response that confirms the affected component is loaded.
- Controlled canary callback if the CVE is about outbound fetch behavior and the program allows it.
- Non-mutating request that demonstrates vulnerable routing or parser behavior.
- Vendor advisory comparison showing deployed version is within affected range.
- Screenshot and raw HTTP response headers with sensitive values redacted.


<div style='page-break-after: always;'></div>


## CVE Discovery Playbook — Nuclei and scanner outputs

Nuclei can be useful for non-invasive detection, but never paste scanner output as the whole report. Verify manually, remove false positives, and explain the exact affected route/version. Use safe templates only and respect automation/rate limits.


### Manual checklist

- Is the asset explicitly in scope?
- Does the program allow known vulnerability/CVE reports?
- Is the product/component positively identified?
- Is the affected version positively identified?
- Does the advisory say this exact version or range is affected?
- Is the vulnerable feature reachable from the internet or by the tested role?
- Can you validate safely without weaponized exploitation?
- Is there a clear confidentiality, integrity, availability, authentication, authorization, or business impact?
- Have you redacted secrets and avoided third-party data?
- Have you included the fixed version and recommended remediation?

### Safe proof ideas

- Version page, manifest, static asset hash, package metadata, plugin metadata.
- Benign endpoint response that confirms the affected component is loaded.
- Controlled canary callback if the CVE is about outbound fetch behavior and the program allows it.
- Non-mutating request that demonstrates vulnerable routing or parser behavior.
- Vendor advisory comparison showing deployed version is within affected range.
- Screenshot and raw HTTP response headers with sensitive values redacted.


<div style='page-break-after: always;'></div>


## CVE Discovery Playbook — CVE classes that are bounty-friendly

CVE hunting is usually most bounty-friendly for exposed admin panels, vulnerable third-party apps in scope, outdated plugins/CMS modules, request smuggling in platform components, vulnerable SSO/OAuth libraries, exposed file managers, vulnerable API gateways, and cloud dashboards. It is less useful for theoretical library CVEs where the vulnerable code path is not used.


### Manual checklist

- Is the asset explicitly in scope?
- Does the program allow known vulnerability/CVE reports?
- Is the product/component positively identified?
- Is the affected version positively identified?
- Does the advisory say this exact version or range is affected?
- Is the vulnerable feature reachable from the internet or by the tested role?
- Can you validate safely without weaponized exploitation?
- Is there a clear confidentiality, integrity, availability, authentication, authorization, or business impact?
- Have you redacted secrets and avoided third-party data?
- Have you included the fixed version and recommended remediation?

### Safe proof ideas

- Version page, manifest, static asset hash, package metadata, plugin metadata.
- Benign endpoint response that confirms the affected component is loaded.
- Controlled canary callback if the CVE is about outbound fetch behavior and the program allows it.
- Non-mutating request that demonstrates vulnerable routing or parser behavior.
- Vendor advisory comparison showing deployed version is within affected range.
- Screenshot and raw HTTP response headers with sensitive values redacted.


<div style='page-break-after: always;'></div>


## CVE Discovery Playbook — CVE classes that are often rejected

Reports are often rejected when they only show a version string, unauthenticated scanner output without validation, vulnerable library present but unreachable, CVE affects a disabled feature, asset out of scope, no security impact, or public exploit attempt violates program rules.


### Manual checklist

- Is the asset explicitly in scope?
- Does the program allow known vulnerability/CVE reports?
- Is the product/component positively identified?
- Is the affected version positively identified?
- Does the advisory say this exact version or range is affected?
- Is the vulnerable feature reachable from the internet or by the tested role?
- Can you validate safely without weaponized exploitation?
- Is there a clear confidentiality, integrity, availability, authentication, authorization, or business impact?
- Have you redacted secrets and avoided third-party data?
- Have you included the fixed version and recommended remediation?

### Safe proof ideas

- Version page, manifest, static asset hash, package metadata, plugin metadata.
- Benign endpoint response that confirms the affected component is loaded.
- Controlled canary callback if the CVE is about outbound fetch behavior and the program allows it.
- Non-mutating request that demonstrates vulnerable routing or parser behavior.
- Vendor advisory comparison showing deployed version is within affected range.
- Screenshot and raw HTTP response headers with sensitive values redacted.


<div style='page-break-after: always;'></div>


## CVE-to-CWE Hunting Crosswalk

Use this crosswalk when HackerOne CVE Discovery highlights a CVE but you want to turn it into a manual bug bounty workflow.

| CVE root cause pattern | Likely CWE family | Manual validation idea | Avoid |
|---|---:|---|---|
| Authentication bypass in product/plugin | CWE-287 / CWE-288 / CWE-306 | Confirm version and affected endpoint; test with your own instance/account if possible | Trying takeover on real accounts |
| Authorization bypass / IDOR | CWE-639 / CWE-862 / CWE-863 | Two-account object swap or role downgrade test | Bulk enumeration |
| Request smuggling / proxy parsing | CWE-444 / CWE-93 | Safe timing/canary proof, no victim capture | Shared cache poisoning or desync harm |
| SSRF in URL fetcher | CWE-918 / CWE-610 | Collaborator callback from controlled URL | Internal scanning / metadata without permission |
| Path traversal / file read | CWE-22 / CWE-35 / CWE-73 | Controlled file or own tenant file proof | Reading sensitive system files |
| File upload RCE/XSS | CWE-434 / CWE-79 | Harmless same-origin render proof | Malware or webshell upload |
| Deserialization | CWE-502 | Safe tamper/integrity proof | Gadget-chain RCE payloads |
| XXE | CWE-611 / CWE-918 | Collaborator callback proof | Local file reads without permission |
| Exposed secrets | CWE-798 / CWE-321 / CWE-532 | Capability proof with read-only/minimal action | Using or spending third-party resources |
| Cache poisoning/deception | CWE-444 / CWE-525-adjacent | Private controlled cache key proof | Poisoning shared pages for users |
| CORS/auth token leak | CWE-346 / CWE-200 | Local page reading your own private data | Involving real victims |
| Business logic flaw | CWE-840 / CWE-20 / CWE-367 | Two-account or tiny race proof | High-volume abuse |


<div style='page-break-after: always;'></div>


## CVE Discovery Practical Workflow: From HackerOne Page to Valid Report

1. **Pick a CVE family, not just a single CVE.** HackerOne CVE Discovery changes frequently, and individual CVEs age quickly. Build repeatable checks for families: exposed CMS plugins, vulnerable API gateways, request smuggling in front-end components, outdated collaboration tools, vulnerable SSO libraries, file managers, image processors, and framework-specific auth bypasses.

2. **Create a target technology inventory.** For each in-scope asset, note server, framework, CDN, API gateway, CMS, plugin, JavaScript framework, backend language, mobile app version, public package versions, and visible third-party apps.

3. **Map CVEs to assets.** Do not start with exploit code. Start with product/version. Ask: where is this technology deployed? Is it reachable? Is it in scope? Is it patched?

4. **Validate with passive evidence first.** Headers, `/version`, `/manifest.json`, package files, static assets, changelogs, source maps, admin login pages, docs, and error pages often reveal enough to establish an affected version.

5. **Use non-invasive probes second.** If a CVE advisory provides a harmless detection request, use it only if program policy allows. Prefer requests that do not modify state, do not consume resources, and do not access data.

6. **Avoid public exploit autopilot.** Public PoCs often contain destructive steps, callbacks, shell payloads, file writes, or denial-of-service behavior. Convert advisories into safe validation instead.

7. **Prove reachability.** A vulnerable library in a bundle is not enough if the vulnerable function is unused. Show that the route/component/feature is enabled.

8. **Prioritize EPSS and recency as hints.** EPSS and HackerOne discovery recency help decide what to check first, but your report succeeds on deployment-specific proof.

9. **Write reports like an engineer can fix them.** Include the product, version, affected path, fixed version, evidence, risk, and recommended upgrade.

10. **Stop at safe proof.** Once you have enough evidence, do not escalate into data access or shell-level proof unless explicitly permitted and necessary.


<div style='page-break-after: always;'></div>


## Authorization Deep Checklist

- Can a user read another user's object by swapping `id`?
- Can a user update another user's object by swapping `id`?
- Can a user delete/archive/restore another user's object?
- Can a user trigger an export job for another tenant?
- Can a user download an export job created by another tenant?
- Can a member perform owner-only actions by calling API directly?
- Can a guest read comments/files/audit logs hidden in UI?
- Can a removed user reuse old links/tokens?
- Can a pending invite user access org resources before acceptance?
- Can a suspended user still access APIs?
- Can a free/trial/expired user access paid features?
- Can a child object be accessed by ID even when parent org ID belongs to attacker?
- Can GraphQL `node(id:)` bypass route-specific checks?
- Can batch endpoints include victim IDs among attacker IDs?
- Can search/filter endpoints return cross-tenant records?
- Can sort/pagination cursors leak objects from another tenant?
- Can export formats include hidden fields returned nowhere else?
- Can webhooks, audit logs, or notifications expose private objects?
- Can API keys created in one org access another org?
- Can stale JWT claims preserve old role after downgrade?


<div style='page-break-after: always;'></div>


## Authentication and Session Deep Checklist

- Does session ID rotate after login?
- Do all sessions revoke after password reset?
- Do old refresh tokens work after password reset?
- Does enabling MFA revoke old sessions?
- Does disabling MFA require current password or MFA challenge?
- Does email change require confirmation from old or new email as appropriate?
- Can reset links be reused?
- Does requesting a new reset link invalidate the old one?
- Are magic links bound to browser/session/email?
- Can OAuth `state` be replayed or swapped?
- Is OIDC `nonce` checked?
- Is `redirect_uri` strictly matched?
- Can login CSRF attach a victim browser to attacker account?
- Can account linking connect attacker IdP to victim account?
- Can invite acceptance authenticate the wrong email?
- Can old sessions access org after user removal?
- Are remember-me tokens invalidated on logout/password reset?
- Are API tokens revoked on account deletion?
- Can device codes be approved by one account and consumed by another?
- Are OTP attempts rate limited per account and token?


<div style='page-break-after: always;'></div>


## File and Parser Deep Checklist

- Can uploaded files be accessed without auth?
- Can uploaded files be accessed cross-tenant?
- Are SVGs rendered on same origin?
- Is HTML served with safe content type and attachment disposition?
- Do filenames reflect into headers or pages?
- Do previews execute scripts?
- Do PDF generators fetch external resources?
- Do image processors fetch remote URLs?
- Do importers follow redirects?
- Do archive imports allow path traversal?
- Do CSV imports allow formula injection in exported spreadsheets?
- Do XML parsers resolve external entities?
- Do DOCX/XLSX/PPTX parsers fetch external relationships?
- Do markdown renderers allow raw HTML?
- Do file conversions leak server errors or paths?
- Do preview endpoints accept arbitrary `url` or `path`?
- Do temporary download URLs expire?
- Are signed URLs bound to object and tenant?
- Can file metadata from Account B appear in Account A search?
- Can deleted files still be downloaded?


<div style='page-break-after: always;'></div>


## CVE Hunting Deep Checklist

- Is the target asset in scope?
- Does the program accept CVE reports?
- Is automated scanning allowed?
- What product and version are exposed?
- What fixed version does the vendor recommend?
- Does NVD/advisory map the CVE to that version?
- Is the affected component enabled?
- Is the vulnerable route reachable?
- Can you validate without destructive payloads?
- Does the CVE require authentication? If yes, can your tested role reach it?
- Does the CVE require a configuration option? Is that option enabled?
- Does the CVE require a plugin/module? Is it installed?
- Does the CVE require a specific backend such as HTTP/2, proxy, database, or parser?
- Can you show exploitability with a benign canary?
- Are there mitigations already present such as WAF, patch backport, disabled feature, or vendor hotfix?
- Could the version string be misleading due to backported patches?
- Did you include exact evidence and advisory links?
- Did you avoid shell, file write, DoS, or data access?
- Did you provide remediation?
- Did you state limitations honestly?


<div style='page-break-after: always;'></div>



# Report-Writing Templates

## CWE report template

```markdown
# Title
[Role/attacker] can [read/change/trigger] [victim resource/action] via [endpoint/parameter], causing [impact]

## Summary
The application does not correctly enforce [authorization/authentication/input validation/etc.] on [endpoint]. Using two accounts I control, I confirmed that [Account A role] can [action] against [Account B/other tenant object].

## Affected asset
- Program asset: https://example.com
- Endpoint: METHOD /api/...
- CWE: CWE-...
- Authentication required: Yes/No
- Roles tested: ...

## Steps to reproduce
1. Create Account A and Account B.
2. In Account B, create [victim object] and note ID `[redacted]`.
3. In Account A, create [attacker object] and capture request `[request name]`.
4. Replace `[field]` with Account B's object ID.
5. Send the request.
6. Observe that [private data returned / state changed].
7. Confirm from Account B that [impact].

## Expected result
Account A should receive 403/404 or should not be able to affect Account B's resource.

## Actual result
Account A can [impact].

## Impact
This allows [cross-tenant read/write, privilege escalation, account takeover, billing manipulation, etc.]. An attacker with a normal account could [realistic abuse path] without needing victim interaction.

## Evidence
- Request/response pairs attached with secrets redacted.
- Screenshots showing before/after state.
- Account IDs and object IDs redacted but available on request.

## Remediation suggestion
Enforce server-side authorization on every access to the object/action. Bind object IDs to the authenticated user's tenant/role. Add regression tests for cross-tenant and low-role access.
```

## CVE report template

```markdown
# Title
In-scope asset appears affected by [CVE-ID] in [product/component] [version], enabling [impact]

## Summary
The asset [URL] exposes [product/component] version [x.y.z], which is affected by [CVE-ID] according to [vendor/NVD/advisory]. The fixed version is [x.y.z]. I validated exposure using non-invasive checks and did not run a destructive exploit.

## Affected asset
- Asset: https://example.com
- Product/component: ...
- Observed version: ...
- Fixed version: ...
- CVE: ...
- CWE if known: ...
- EPSS/CVSS/KEV context: ...

## Safe validation performed
1. Confirmed product and version from [header/page/manifest/static asset/hash/admin page].
2. Confirmed vulnerable component is reachable at [path].
3. Confirmed advisory states versions before [fixed] are affected.
4. Performed only [benign request/version check/canary]. No destructive payloads were used.

## Impact
If exploited, this CVE can allow [impact from advisory] under [conditions]. In this deployment, the risky component is reachable because [evidence].

## Evidence
- Screenshots / HTTP response snippets with version.
- Advisory/NVD links.
- Non-invasive reproduction notes.

## Remediation suggestion
Upgrade [component] to [fixed version] or later, disable the affected feature if unused, and verify that public version exposure no longer indicates the vulnerable release.
```


<div style='page-break-after: always;'></div>


## Tooling Appendix

## Intercept and replay

- **Burp Suite Community/Professional**: best all-around manual testing proxy. Use Repeater, Comparer, Logger, Proxy history, Intruder with small safe counts, Collaborator, and extensions carefully.
- **Caido**: fast modern proxy/replay workflow with good project organization.
- **OWASP ZAP**: useful free proxy and passive scanning option.

## Discovery

- **katana / hakrawler**: crawl in-scope URLs and JS-discovered endpoints.
- **gau / waybackurls**: collect historical URLs. Verify scope before testing.
- **ffuf / feroxbuster / gobuster**: content discovery. Use low rates and obey policy.
- **arjun / Param Miner**: discover hidden parameters. Treat results as leads.

## API testing

- **Postman / Insomnia / Bruno**: organize API collections.
- **jq**: filter and compare JSON.
- **GraphQL clients**: test queries/mutations where GraphQL is exposed and permitted.
- **GraphQL Voyager**: visualize schemas only where introspection is permitted.

## Auth/session

- **jwt_tool / jose / jwt.io**: inspect JWTs. Do not brute force secrets without permission.
- **SAML-tracer**: inspect SAML flows in browser.
- **Cookie editors**: compare and clear session tokens.

## OAST/callbacks

- **Burp Collaborator**: SSRF, blind XSS, blind XXE, webhook verification.
- **Interactsh**: open-source OAST server/client.
- **Controlled VPS logs**: useful for detailed request headers and source IPs.

## Secrets and source review

- **trufflehog / gitleaks**: in-scope repos/assets only.
- **Semgrep**: source review and pattern checks.
- **jadx / apktool**: mobile apps only where reverse engineering/testing is allowed.

## CVE/version validation

- **Wappalyzer / WhatWeb**: initial fingerprinting.
- **Nuclei**: non-invasive templates only; verify manually.
- **NVD / vendor advisories / GitHub Security Advisories**: confirm affected/fixed versions.
- **EPSS**: prioritize likely exploitation risk, not a substitute for proof.

## Documentation discipline

Keep a per-target notebook with:

- program scope and rules;
- accounts and roles;
- object ID map;
- endpoint map;
- interesting parameters;
- tested authorization pairs;
- CVE/version findings;
- duplicates searched;
- report evidence ready for redaction.


<div style='page-break-after: always;'></div>


## Informative-Only Traps and How to Upgrade Them

## Missing security headers

Usually informative unless a missing header enables a concrete exploit. Upgrade by chaining with XSS, clickjacking on a sensitive action, or token leakage. Do not report generic missing headers alone unless the program explicitly accepts them.

## Version disclosure

Usually informative unless the version is affected by a relevant CVE and the vulnerable feature is reachable. Upgrade by mapping version to advisory and safe validation.

## Open redirect

Often low or informative alone. Upgrade by chaining to OAuth code theft, SSO RelayState, magic link redirection, post-login token leakage, or trusted-domain phishing only if program accepts phishing-adjacent risk.

## Self-XSS

Usually informative. Upgrade only if there is a realistic way to make another user/admin execute it, such as stored XSS in support dashboard, CSV import rendered by admin, or OAuth/login CSRF chain.

## CORS wildcard

Not a bug by itself. Upgrade by proving credentialed cross-origin read of private data from your own account.

## Rate limit missing

Often low unless it affects login, OTP, recovery, financial abuse, email/SMS cost, or business flow. Upgrade with small safe evidence and impact math, not brute force.

## Scanner CVE finding

Not enough. Upgrade by confirming product, version, reachability, advisory mapping, and safe validation.

## Stack trace

Often low unless it reveals secrets, credentials, internal endpoints enabling access, or sensitive PII. Upgrade by showing the exposed sensitive field and why it matters.

## Public bucket/object listing

Not always a bug if content is intended public. Upgrade by finding private, sensitive, or cross-tenant data, but do not download bulk data.

## Clickjacking

Often informative unless sensitive state-changing action can be framed and triggered. Upgrade with a safe clickjacking PoC against your own account and a meaningful action.


<div style='page-break-after: always;'></div>


## Source Links and Reference Map

- [HackerOne CWE Discovery](https://hackerone.com/hacktivity/cwe_discovery)
- [HackerOne CVE Discovery](https://hackerone.com/hacktivity/cve_discovery)
- [HackerOne Hacktivity](https://hackerone.com/hacktivity/overview)
- [CWE MITRE List](https://cwe.mitre.org/data/index.html)
- [CVE Program overview](https://www.cve.org/About/Overview)
- [NVD Vulnerabilities](https://nvd.nist.gov/vuln)
- [FIRST EPSS](https://www.first.org/epss/)
- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [OWASP API Security Top 10 2023](https://owasp.org/API-Security/editions/2023/en/0x11-t10/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [Bugcrowd VRT](https://github.com/bugcrowd/vulnerability-rating-taxonomy)

Note: HackerOne discovery pages are JavaScript-rendered. Search index snippets and page metadata can expose useful high-level descriptions, while detailed definitions and testing methodology should be cross-checked with MITRE CWE, NVD, OWASP, PortSwigger, vendor advisories, and program policy.


<div style='page-break-after: always;'></div>



---

**Approximate length:** 19,331 words. At ~450 words/page, roughly 42 pages depending on Markdown renderer.


<div style='page-break-after: always;'></div>

# Additional HackerOne CWE/CVE Niche Recipes

These recipes are scenario-driven. They combine multiple CWE classes because real HackerOne reports rarely fit neatly into a single weakness bucket. Use them to decide what to test when a target has a particular feature.


<div style='page-break-after: always;'></div>

## SaaS tenant boundary niche

SaaS applications are excellent for CWE-driven hunting because they naturally create many permission boundaries: user, team, organization, workspace, project, billing account, environment, integration, and data region. The low-hanging mistake is assuming that because the UI only shows objects from the current tenant, the API also enforces tenant boundaries. In reality, APIs often take both a parent tenant ID and a child object ID, then validate only one of them.

Manual workflow:

1. Create Organization A and Organization B using accounts you control.
2. Create the same object type in both: project, file, webhook, API key, invoice, report, dashboard, ticket, data source.
3. Capture all read and write requests from Organization A.
4. Swap child IDs from Organization B while leaving the Organization A parent ID intact.
5. Swap the parent ID while leaving child ID intact.
6. Test batch endpoints with a mixed array containing one allowed ID and one forbidden ID.
7. Test search endpoints with filters that reference tenant IDs, owner IDs, or workspace IDs.
8. Test background jobs: export creation, export status, export download, report generation, report download.
9. Confirm state from both organizations.

CWEs that frequently apply: CWE-639, CWE-862, CWE-863, CWE-915, CWE-20, CWE-200, CWE-201.

Strong impact examples: cross-tenant invoice read, cross-tenant report export, changing another organization's webhook URL, inviting an admin into another workspace, reading audit logs for a separate tenant, or using one tenant's API key to access another tenant. Weak examples: seeing a public organization slug, changing your own object in a shared organization, or receiving a generic 403 with no leak.


<div style='page-break-after: always;'></div>

## Billing and subscription niche

Billing flows are full of manually testable trust assumptions. Programs may treat billing carefully, so never perform real unauthorized purchases, refunds, or payment abuse. Use sandbox modes, free/trial plans, tiny reversible changes, or stop at proof of server-side acceptance where no harm occurs. The aim is not to steal service; it is to show that the server trusts client-controlled plan, price, quantity, currency, coupon, tax, billing account, or entitlement fields.

Manual workflow:

1. Compare free, trial, paid, expired, cancelled, and downgraded states if you can create them safely.
2. Capture plan upgrade/downgrade requests and check which fields are client supplied.
3. Remove or change `price_id`, `plan_id`, `amount`, `currency`, `quantity`, `trial_days`, `coupon`, `discount`, `tax`, `seats`, `billing_account_id`, and `entitlements`.
4. Test whether the backend recalculates price or trusts the browser.
5. Test replay of old checkout sessions after downgrade/cancel.
6. Test coupon single-use, invite seat limits, trial extension, and plan limits with tiny proof.
7. Test whether an expired account can still use paid APIs directly.
8. Test whether export/API/webhook/AI features enforce quota server-side.

CWEs that frequently apply: CWE-20, CWE-367, CWE-400, CWE-639, CWE-862, CWE-915.

Strong impact examples: paid feature access without entitlement, coupon reuse, seat limit bypass, downgrade not revoking privileged features, cross-tenant billing read, or invoice modification. Weak examples: frontend price display manipulation with no server-side effect, harmless UI mismatch, or speculative impact without confirming entitlement change.


<div style='page-break-after: always;'></div>

## GraphQL niche

GraphQL creates excellent manual opportunities because one endpoint can expose many object types and mutations. The mistake is assuming that if the UI never asks for a sensitive field, users cannot ask for it. Another common mistake is enforcing authorization on list queries but not on `node(id:)`, nested relationships, mutations, or batch loaders.

Manual workflow:

1. Capture normal GraphQL queries and mutations.
2. Identify variables containing `id`, `nodeId`, `organizationId`, `projectId`, `ownerId`, `userId`, `viewerId`, `teamId`, or `input` objects.
3. Replay queries with IDs from another account/tenant you control.
4. Try equivalent access through `node(id:)`, search queries, nested relationships, and mutations.
5. Add fields that appear in responses elsewhere: `email`, `role`, `permissions`, `billing`, `apiKeys`, `tokens`, `private`, `owner`, `members`, `auditLogs`.
6. Test mutations for mass assignment by adding hidden fields inside `input`.
7. Test aliases and batching only in small safe counts.
8. If introspection is disabled, use observed queries from JS bundles and network logs.

CWEs that frequently apply: CWE-639, CWE-862, CWE-863, CWE-915, CWE-200, CWE-201, CWE-20.

Strong impact examples: querying another tenant's private object by global node ID, adding yourself to an org through mutation, reading hidden billing fields, or changing role through an input field. Weak examples: introspection enabled alone unless policy accepts it, schema names without data, or querying fields that correctly return null/forbidden.


<div style='page-break-after: always;'></div>

## Mobile-backed API niche

Mobile apps often use the same backend as the web app but expose different endpoints, older versions, additional debug metadata, or weaker authorization assumptions. Only reverse engineer or proxy mobile apps if the program allows it. Use your own device, your own account, and avoid bypassing protections if prohibited.

Manual workflow:

1. Install the in-scope app and create test accounts.
2. Proxy traffic through Burp/mitmproxy if allowed.
3. Compare mobile endpoints to web endpoints.
4. Look for old API versions, mobile-only routes, feature flags, device IDs, and debug endpoints.
5. Check whether mobile routes enforce the same object/role permissions.
6. Inspect local storage for tokens, refresh tokens, API keys, private data, or logs.
7. Check whether logout/password reset revokes mobile refresh tokens.
8. Check certificate validation only in a controlled environment and only if allowed.

CWEs that frequently apply: CWE-287, CWE-288, CWE-613, CWE-639, CWE-862, CWE-922, CWE-312, CWE-295, CWE-798.

Strong impact examples: mobile endpoint bypasses admin checks, stale mobile token remains valid after password reset, sensitive tokens stored in plaintext, or mobile app contains overprivileged hard-coded secrets. Weak examples: public analytics keys, normal cached non-sensitive data, or route names with no access.


<div style='page-break-after: always;'></div>

## OAuth/OIDC and SSO niche

OAuth, OIDC, and SSO flows contain many small binding requirements. Most high-value findings come from missing binding between the auth response and the initiating session: `state`, `nonce`, `redirect_uri`, `code_verifier`, issuer, audience, tenant, email, and account linking identity. Test only with accounts and identity providers you control.

Manual workflow:

1. Capture the full authorization request and callback.
2. Verify that `state` is unique, unguessable, single-use, and bound to the initiating session.
3. Verify that OIDC `nonce` is checked.
4. Verify that `redirect_uri` is strict and cannot be loosened through open redirect chains.
5. Start login as Account A and attempt to complete with Account B only using your own accounts.
6. Test account linking while logged into one account and authorizing another provider identity.
7. Test SSO tenant binding: a login for Organization A should not authenticate into Organization B.
8. Test stale SSO sessions after role removal or SSO deprovisioning.

CWEs that frequently apply: CWE-287, CWE-288, CWE-345, CWE-346, CWE-352, CWE-601, CWE-613, CWE-862.

Strong impact examples: login CSRF, account linking takeover, OAuth code theft through redirect chain, SSO tenant confusion, or bypassing enforced SSO. Weak examples: missing `state` with no exploitability because no session/action is affected, or theoretical redirect issues with no auth-chain impact.


<div style='page-break-after: always;'></div>

## Webhook and integration niche

Webhook features mix outbound requests, inbound trust, signatures, retries, secrets, logs, and tenant boundaries. This makes them one of the richest manual niches. Create integrations only against infrastructure you control. Never send secrets to third-party endpoints you do not control.

Manual workflow:

1. Configure a webhook pointing to your controlled endpoint.
2. Capture payload, headers, signature, timestamp, delivery ID, retry behavior, and secret handling.
3. Check whether webhook secrets appear in UI, logs, exports, or lower-role views.
4. Replay webhook requests to inbound endpoints and test whether signatures/timestamps are enforced.
5. Change tenant/resource IDs inside payloads if inbound webhooks exist.
6. Check whether low-privileged users can configure webhooks that send high-privileged data.
7. Check whether webhook test buttons can SSRF or reach arbitrary domains.
8. Check whether delivery logs expose Authorization headers or private payloads cross-tenant.

CWEs that frequently apply: CWE-918, CWE-345, CWE-346, CWE-798, CWE-532, CWE-639, CWE-862, CWE-863, CWE-610.

Strong impact examples: forged webhook events accepted without signature, cross-tenant webhook log read, admin-only data sent to member-created webhook, SSRF through webhook test, or exposed webhook signing secret. Weak examples: webhook sends data the configuring admin is allowed to receive, or a signature format preference without bypass.


<div style='page-break-after: always;'></div>

## File preview and document conversion niche

File previewers are a crossroads for XSS, SSRF, XXE, path traversal, upload validation, archive extraction, and resource consumption. The trick is to test renderers and converters with harmless files that expose parser behavior without causing damage. Use files you own and avoid huge files or decompression bombs.

Manual workflow:

1. Upload benign files of each supported type: TXT, CSV, PDF, SVG, DOCX, XLSX, ZIP, XML, HTML if allowed.
2. Observe storage URL, rendering origin, content type, content disposition, and cache headers.
3. Check whether SVG/HTML/Markdown executes on same origin.
4. Check whether document converters fetch external images/styles from your controlled domain.
5. Check whether XML-based formats trigger external callbacks.
6. Check whether archives preserve unsafe paths using harmless filenames.
7. Check whether previews are accessible after file deletion, share revocation, or user removal.
8. Check whether another tenant can access preview URLs.

CWEs that frequently apply: CWE-434, CWE-79, CWE-918, CWE-611, CWE-22, CWE-35, CWE-73, CWE-400, CWE-639.

Strong impact examples: stored XSS in same-origin preview, server callback from converter, cross-tenant preview access, file read through traversal, or sensitive document accessible after revocation. Weak examples: file extension bypass where file is stored safely as attachment on a separate static origin.


<div style='page-break-after: always;'></div>

## Search, export, and reporting niche

Search and export endpoints often aggregate data from many objects and are less thoroughly authorization-tested than normal object read APIs. They are great for cross-tenant data leaks because engineers may authorize access to the dashboard but forget row-level filtering inside the report builder.

Manual workflow:

1. Create unique canary data in Account B: distinctive project name, comment, invoice label, file title, ticket text.
2. Search from Account A for the canary string.
3. Test filters: owner, org, date range, status, type, archived, deleted, shared, private.
4. Test export jobs: create, list, status, download.
5. Test CSV/PDF/XLSX exports for hidden fields that UI hides.
6. Test report templates created by admin but viewed by member.
7. Test old export links after permission removal.
8. Test pagination cursors and sort keys for leakage.

CWEs that frequently apply: CWE-200, CWE-201, CWE-359, CWE-639, CWE-862, CWE-863, CWE-915.

Strong impact examples: another tenant's records in search/export, private fields in member exports, stale export download after permission revoke, or report builder exposing billing/PII. Weak examples: search returns public profile data or object counts with no sensitive impact.


<div style='page-break-after: always;'></div>

## Cache behavior niche

Caching bugs can be impactful but must be tested cautiously. Do not poison shared caches with harmful content. Use unique cache-buster paths, your own account, and harmless markers. Look for mismatches between cache key and response variation: authentication, host, headers, query params, path normalization, content negotiation, and cookies.

Manual workflow:

1. Identify cacheable responses: static-ish API responses, profile pages, dashboards, PDFs, redirects, error pages.
2. Check headers: `Cache-Control`, `Vary`, `Age`, `X-Cache`, CDN headers.
3. Add a harmless marker through a header or parameter and see if it appears in a cached response only on a unique URL you control.
4. Test whether authenticated content is cached and served to a logged-out or different controlled account.
5. Test path confusion: `/profile`, `/profile/anything.css`, encoded paths, trailing slash.
6. Test open redirect + cache poisoning only with self-contained harmless content.
7. Test web cache deception against your own private profile path.

CWEs that frequently apply: CWE-444, CWE-525-adjacent session/cache issues, CWE-200, CWE-201, CWE-79, CWE-601.

Strong impact examples: private data cached publicly, security-sensitive redirect cached, cache poisoning leading to stored XSS on a shared page, or web cache deception exposing private content. Weak examples: cache headers on public static files, or theoretical cache behavior without a second-user proof.


<div style='page-break-after: always;'></div>

## Admin and support dashboard niche

Admin/support dashboards are often not directly accessible, but user-controlled data may be rendered there: support tickets, names, organization metadata, logs, webhook payloads, file previews, billing notes, and crash reports. This is where self-XSS can become stored XSS against staff if the program accepts staff-impact testing. Be careful: many programs prohibit targeting employees. Only test staff/admin surfaces if the program allows it, or use a role you can create yourself.

Manual workflow:

1. Identify user-controlled fields likely viewed by privileged users.
2. Prefer a controlled admin role you can create, such as organization owner/admin.
3. Test stored XSS/HTML injection with harmless canaries.
4. Test log injection, webhook payload rendering, filename rendering, CSV formula injection, and markdown rendering.
5. Test IDOR from admin-like org owner to another org only using your own tenants.
6. Test whether support bundles include secrets or other tenants' data.
7. Test whether audit logs expose sensitive headers or tokens.

CWEs that frequently apply: CWE-79, CWE-93, CWE-113, CWE-532, CWE-200, CWE-201, CWE-639, CWE-862.

Strong impact examples: stored XSS in admin dashboard, support log exposing tokens, admin-only data accessible to members, or webhook payload causing script execution in delivery log. Weak examples: self-XSS visible only to the submitter, or theoretical staff impact forbidden by program policy.


<div style='page-break-after: always;'></div>

## API key and token scope niche

API keys are often created with labels like read-only, project-only, integration-only, or environment-specific. The manual opportunity is to test whether the scope is actually enforced on every endpoint and whether scope changes/revocations propagate to existing tokens.

Manual workflow:

1. Create multiple API keys with different scopes if the app supports it.
2. Attempt harmless read with write-only key and harmless write with read-only key.
3. Attempt project A key on project B.
4. Attempt org A key on org B.
5. Rotate/revoke a key and replay old requests.
6. Downgrade the user who created the key and test whether the key keeps old power.
7. Delete/leave org and test old key.
8. Check whether keys appear in logs, exports, browser storage, or lower-role views.

CWEs that frequently apply: CWE-269, CWE-250, CWE-862, CWE-863, CWE-613, CWE-798, CWE-532, CWE-639.

Strong impact examples: read-only key can write, project key can access all projects, revoked key remains valid, or member-created token has owner powers. Weak examples: API key prefix/last-four visible by design.


<div style='page-break-after: always;'></div>

## Invite, membership, and role transition niche

Invites and role transitions are fragile because they involve identity, authorization, token lifetime, and state changes. Bugs often appear when a user is invited, removed, reinvited, downgraded, suspended, or accepts with a different email/provider.

Manual workflow:

1. Invite Account B to Organization A with low role.
2. Capture invite token and acceptance requests.
3. Try accepting after revocation, after role change, after expiration, and after email change.
4. Try accepting while logged into the wrong account you control.
5. Test whether invite role can be upgraded by changing request fields.
6. Remove Account B and test old session/API access.
7. Downgrade admin to member and test old admin requests.
8. Test pending user access before acceptance.

CWEs that frequently apply: CWE-287, CWE-288, CWE-640, CWE-613, CWE-639, CWE-862, CWE-863, CWE-915.

Strong impact examples: accepting an invite for another email, changing invite role to admin, removed user retains access, or pending invite can access private org resources. Weak examples: invite token format disclosure without reuse or bypass.


<div style='page-break-after: always;'></div>

## Custom domain and tenant routing niche

Custom domains introduce routing, verification, certificate, takeover, and tenant-binding issues. Only test domains you own. Never claim or interfere with domains belonging to other users.

Manual workflow:

1. Add a domain you control to Tenant A.
2. Observe verification method: DNS TXT, CNAME, HTTP file, email, or automatic.
3. Try reusing verification token across Tenant B.
4. Remove domain from Tenant A and test whether it can still route to Tenant A.
5. Test whether Tenant B can claim a domain still bound to Tenant A.
6. Test wildcard behavior and subdomain binding using only your domains.
7. Check TLS issuance and certificate validation behavior.
8. Test whether custom domain routes leak tenant data or bypass auth.

CWEs that frequently apply: CWE-345, CWE-346, CWE-862, CWE-863, CWE-610, CWE-295, CWE-639.

Strong impact examples: tenant takeover through domain claim confusion, stale domain binding, cross-tenant routing, or unverified domain serving another tenant. Weak examples: inability to add a domain you do not own due to proper verification.


<div style='page-break-after: always;'></div>

## AI/LLM feature niche

AI features increasingly appear in HackerOne programs and can map to traditional CWEs when they touch authorization, data exposure, integrations, file processing, or resource consumption. Treat prompt injection as reportable only when it causes unauthorized data access, action, or security boundary bypass under program rules.

Manual workflow:

1. Identify what data the AI feature can access: user docs, org data, tickets, code, integrations, web browsing, file uploads.
2. Test tenant boundaries: can prompts retrieve another user's or tenant's data?
3. Test role boundaries: can a member ask for admin-only data?
4. Test tool/action boundaries: can AI trigger actions the user cannot perform directly?
5. Test indirect prompt injection only in controlled documents you own.
6. Test file uploads and URL fetchers for SSRF/parser issues safely.
7. Test quota/cost controls with tiny safe prompts.
8. Test whether chat histories or generated exports leak secrets.

CWEs that frequently apply: CWE-862, CWE-863, CWE-639, CWE-200, CWE-201, CWE-918, CWE-434, CWE-400, CWE-20.

Strong impact examples: AI retrieves another tenant's private data, executes unauthorized integration action, leaks hidden system/tool secrets with security impact, or fetches controlled external URL server-side. Weak examples: generic jailbreak with no protected data/action, or model hallucination.


<div style='page-break-after: always;'></div>

## CVE triage for CMS/plugin ecosystems

CMS and plugin ecosystems are common CVE-hunting targets because versioned plugins are often exposed through static files, readme files, changelogs, asset paths, and admin pages. However, many programs reject reports that only show a plugin exists. You must show affected version and reachable vulnerable feature.

Manual workflow:

1. Identify CMS and plugins/themes/modules from static paths, generator tags, REST routes, asset names, and readme files.
2. Confirm version from multiple sources if possible.
3. Check vendor advisory for affected and fixed versions.
4. Determine whether vulnerable feature is enabled: form, shortcode, upload, endpoint, REST route, AJAX action, admin page.
5. Validate with a benign request that does not alter data or exploit users.
6. Confirm unauthenticated vs authenticated requirements match your access level.
7. Avoid public exploit payloads that create users, write files, or dump data.
8. Report fixed version and exact plugin path/version evidence.

CWEs that frequently apply: depends on CVE; often CWE-79, CWE-89, CWE-862, CWE-434, CWE-22, CWE-352, CWE-287.

Strong impact examples: outdated plugin with reachable unauthenticated auth bypass, file upload, SQLi safe proof, or stored XSS in admin context. Weak examples: disabled plugin, version hidden behind backport, or vulnerable library not used.


<div style='page-break-after: always;'></div>

## CVE triage for API gateways and reverse proxies

API gateways, proxies, and load balancers are common sources of request routing, auth bypass, SSRF, header trust, and request smuggling CVEs. These bugs are sensitive; test only with safe methods and policy approval.

Manual workflow:

1. Fingerprint gateway/proxy from headers, error pages, protocol behavior, docs, and asset naming.
2. Check known CVEs for exact version or affected behavior.
3. Determine if the target is behind the affected component and whether the vulnerable mode is enabled.
4. Use safe protocol probes, not destructive desync or cache poisoning.
5. Test header trust issues only against your own account/tenant.
6. Check `X-Forwarded-*`, host, scheme, path rewrite, method override, and routing headers.
7. Check if front-end auth differs from backend routing.
8. Document exact request/response and why the gateway likely processes it incorrectly.

CWEs that frequently apply: CWE-444, CWE-93, CWE-113, CWE-346, CWE-862, CWE-918, CWE-601.

Strong impact examples: front-end auth bypass to protected backend route, safe request smuggling proof, host header password reset poisoning, or SSRF through gateway route. Weak examples: unusual header reflected with no impact or generic proxy version disclosure.


<div style='page-break-after: always;'></div>

## Final Field Checklist Before Submitting

- I confirmed the asset is in scope.
- I checked program policy for automation, CVE reports, staff-impact testing, DoS, and known vulnerabilities.
- I used only accounts, tenants, files, domains, and data that I control.
- I did not access real user data beyond unavoidable metadata necessary to prove impact.
- I avoided destructive payloads, stress testing, persistence, malware, and shell-level exploitation unless explicitly permitted.
- I can explain the exact security boundary that failed.
- I can reproduce the bug with minimal steps.
- I have before/after evidence.
- I redacted tokens, cookies, secrets, and private IDs.
- I included CWE/CVE mapping only as support, not as the whole report.
- I explained business impact in plain language.
- I included likely remediation.
- I searched for duplicates in public Hacktivity and program disclosure notes where possible.
- I did not inflate severity beyond demonstrated impact.
- I stopped testing once enough proof existed.


---

**Updated approximate length:** 22,824 words. At ~450 words/page, roughly 50 pages depending on renderer, with 76 explicit page breaks.

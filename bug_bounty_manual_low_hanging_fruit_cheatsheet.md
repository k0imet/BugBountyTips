# Manual Bug Bounty Cheatsheet: Low-Hanging Fruits and High-Impact Manual Test Classes

**Generated:** 2026-05-05  
**Scope assumption:** This guide is for **authorized bug bounty, VDP, pentest, or lab environments only**. Do not test systems without written authorization. Do not access real user data, do not persist payloads in production-facing areas that other users may trigger, do not dump databases, do not run high-volume scans, and do not perform destructive actions.

**Interpretation note:** Your phrase “both authenticated and authenticated” appears to mean **unauthenticated and authenticated**. This cheatsheet covers both.

**Design goal:** Find bugs that triage teams usually consider more than “informative” by proving a concrete security impact: unauthorized data access, unauthorized state change, account takeover, privilege escalation, tenant escape, payment/business abuse, code execution in a permitted test context, sensitive token exposure, or meaningful bypass of a security control.

**Primary source anchors:** This guide is aligned with Bugcrowd’s VRT as a baseline severity taxonomy; OWASP WSTG, OWASP Top 10, OWASP API Top 10, OWASP Cheat Sheet Series; PortSwigger Web Security Academy; and selected bug bounty/practitioner methodology writeups. Links are collected in the Sources section at the end.

---

## How to use this file

Read Pages 1–10 first. They define the testing mindset, evidence model, impact threshold, and safe setup. Then use the per-bug pages as a checklist while testing a target. Each vulnerability page is intentionally repetitive: the same loop appears again and again because most valid manual bug bounty findings come from disciplined comparison, not from firing random payloads.

A good manual testing loop is:

1. **Map functionality**: find the endpoint, UI action, API route, object ID, role check, workflow state, token, or boundary.
2. **Create two controlled identities**: Account A and Account B, preferably in different orgs/tenants when allowed.
3. **Capture baseline requests**: use Burp/ZAP/DevTools. Save raw request and raw response.
4. **Change exactly one thing**: object ID, org ID, role, method, token, email, price, quantity, flow step, header, or parameter.
5. **Compare results**: status code, body length, response fields, side effect in UI, audit log, email/SMS side effect, object state.
6. **Prove impact safely**: use your own accounts and your own test data. Stop as soon as the impact is clear.
7. **Write a concise report**: prerequisites, affected endpoint, steps, evidence, impact, suggested remediation, and why it is in scope.


## Table of Contents

- [Page 1: Operating Rules, Authorization, and Safety Boundaries](#page-1-operating-rules-authorization-and-safety-boundaries)
- [Page 2: Impact-First Bug Selection: Avoid Informative-Only Traps](#page-2-impact-first-bug-selection-avoid-informative-only-traps)
- [Page 3: Bugcrowd VRT-Aligned Severity Thinking](#page-3-bugcrowd-vrt-aligned-severity-thinking)
- [Page 4: Manual Testing Environment and Tool Stack](#page-4-manual-testing-environment-and-tool-stack)
- [Page 5: The Universal Two-Account Differential Method](#page-5-the-universal-two-account-differential-method)
- [Page 6: Recon for Manual Testing Without Becoming Noise](#page-6-recon-for-manual-testing-without-becoming-noise)
- [Page 7: Reportability Matrix: Informative vs Valid](#page-7-reportability-matrix-informative-vs-valid)
- [Page 8: Unauthenticated Access Boundary Checks](#page-8-unauthenticated-access-boundary-checks)
- [Page 9: IDOR / BOLA: Read Another User or Tenant Object](#page-9-idor--bola-read-another-user-or-tenant-object)
- [Page 10: IDOR / BOLA: Write, Delete, or State-Change Another Object](#page-10-idor--bola-write-delete-or-state-change-another-object)
- [Page 11: Broken Function Level Authorization: User Calls Admin Endpoint](#page-11-broken-function-level-authorization-user-calls-admin-endpoint)
- [Page 12: Broken Object Property Level Authorization / Mass Assignment](#page-12-broken-object-property-level-authorization--mass-assignment)
- [Page 13: Multi-Tenant Isolation and Organization Boundary Bugs](#page-13-multi-tenant-isolation-and-organization-boundary-bugs)
- [Page 14: Invite, Team, and Role Workflow Flaws](#page-14-invite-team-and-role-workflow-flaws)
- [Page 15: Account Registration and Email Verification Bypass](#page-15-account-registration-and-email-verification-bypass)
- [Page 16: Password Reset Token Weakness and Account Takeover Paths](#page-16-password-reset-token-weakness-and-account-takeover-paths)
- [Page 17: Change Email / Change Password Authorization Gaps](#page-17-change-email--change-password-authorization-gaps)
- [Page 18: MFA Enrollment, Removal, Recovery, and Step-Up Bypass](#page-18-mfa-enrollment-removal-recovery-and-step-up-bypass)
- [Page 19: Session Fixation, Logout, Cookie, and Token Lifecycle Bugs](#page-19-session-fixation-logout-cookie-and-token-lifecycle-bugs)
- [Page 20: OAuth / OIDC Redirect, State, Scope, and Account Linking Bugs](#page-20-oauth--oidc-redirect-state-scope-and-account-linking-bugs)
- [Page 21: JWT Claim Tampering and Signature Verification Flaws](#page-21-jwt-claim-tampering-and-signature-verification-flaws)
- [Page 22: CSRF on Meaningful State-Changing Actions](#page-22-csrf-on-meaningful-state-changing-actions)
- [Page 23: CORS Misconfiguration With Credentialed Data Theft](#page-23-cors-misconfiguration-with-credentialed-data-theft)
- [Page 24: Reflected XSS With Context-Aware Payloading](#page-24-reflected-xss-with-context-aware-payloading)
- [Page 25: Stored XSS in Shared or Privileged Views](#page-25-stored-xss-in-shared-or-privileged-views)
- [Page 26: DOM XSS and Client-Side Route Injection](#page-26-dom-xss-and-client-side-route-injection)
- [Page 27: Open Redirect With Real Security Impact](#page-27-open-redirect-with-real-security-impact)
- [Page 28: Clickjacking on Sensitive Actions](#page-28-clickjacking-on-sensitive-actions)
- [Page 29: File Upload: Type, Extension, Content, and Serving Bugs](#page-29-file-upload-type-extension-content-and-serving-bugs)
- [Page 30: File Upload to Code Execution: Safe Boundary](#page-30-file-upload-to-code-execution-safe-boundary)
- [Page 31: Path Traversal and Arbitrary File Read](#page-31-path-traversal-and-arbitrary-file-read)
- [Page 32: SSRF: URL Fetchers, Webhooks, Importers, and Metadata Risk](#page-32-ssrf-url-fetchers-webhooks-importers-and-metadata-risk)
- [Page 33: XXE in XML, SVG, Office, SAML, SOAP, and Importers](#page-33-xxe-in-xml-svg-office-saml-soap-and-importers)
- [Page 34: SQL Injection: Safe Manual Detection](#page-34-sql-injection-safe-manual-detection)
- [Page 35: NoSQL Injection in JSON APIs and Login/Search Filters](#page-35-nosql-injection-in-json-apis-and-loginsearch-filters)
- [Page 36: Server-Side Template Injection: Math Probe to Impact](#page-36-server-side-template-injection-math-probe-to-impact)
- [Page 37: Command Injection: Minimal Non-Destructive Proof](#page-37-command-injection-minimal-non-destructive-proof)
- [Page 38: HTTP Request Smuggling and Desync: Manual Triage](#page-38-http-request-smuggling-and-desync-manual-triage)
- [Page 39: Web Cache Poisoning](#page-39-web-cache-poisoning)
- [Page 40: Web Cache Deception](#page-40-web-cache-deception)
- [Page 41: GraphQL: Introspection, BOLA, BFLA, and Over-Posting](#page-41-graphql-introspection-bola-bfla-and-over-posting)
- [Page 42: WebSocket Authorization and Message Tampering](#page-42-websocket-authorization-and-message-tampering)
- [Page 43: Business Logic: Workflow Step Skipping](#page-43-business-logic-workflow-step-skipping)
- [Page 44: Business Logic: Price, Quantity, Coupon, and Subscription Tampering](#page-44-business-logic-price-quantity-coupon-and-subscription-tampering)
- [Page 45: Race Conditions and Double-Spend Logic](#page-45-race-conditions-and-double-spend-logic)
- [Page 46: Rate Limits on Security-Sensitive and Costly Flows](#page-46-rate-limits-on-security-sensitive-and-costly-flows)
- [Page 47: Sensitive Data Exposure in Responses, Exports, Logs, and Source Maps](#page-47-sensitive-data-exposure-in-responses-exports-logs-and-source-maps)
- [Page 48: Cloud Storage and Public Bucket Exposure](#page-48-cloud-storage-and-public-bucket-exposure)
- [Page 49: Subdomain Takeover and Dangling External References](#page-49-subdomain-takeover-and-dangling-external-references)
- [Page 50: Default Credentials and Exposed Admin Consoles](#page-50-default-credentials-and-exposed-admin-consoles)
- [Page 51: API Versioning and Deprecated Endpoint Authorization Gaps](#page-51-api-versioning-and-deprecated-endpoint-authorization-gaps)
- [Page 52: Mobile API and Thick Client Assumption Bugs](#page-52-mobile-api-and-thick-client-assumption-bugs)
- [Page 53: Webhook and Integration Security Bugs](#page-53-webhook-and-integration-security-bugs)
- [Page 54: PDF, CSV, Spreadsheet, and Report Generation Bugs](#page-54-pdf-csv-spreadsheet-and-report-generation-bugs)
- [Page 55: Search, Filter, Sort, and Pagination Edge Cases](#page-55-search-filter-sort-and-pagination-edge-cases)
- [Page 56: Method Override, Verb Tampering, and Content-Type Confusion](#page-56-method-override-verb-tampering-and-content-type-confusion)
- [Page 57: Referer, Token, and Link Leakage](#page-57-referer-token-and-link-leakage)
- [Page 58: Email, Notification, and Template Injection](#page-58-email-notification-and-template-injection)
- [Page 59: SAML/SSO Configuration and Tenant Binding Bugs](#page-59-samlsso-configuration-and-tenant-binding-bugs)
- [Page 60: Access Control in Export, Import, and Bulk Actions](#page-60-access-control-in-export-import-and-bulk-actions)
- [Page 61: Asynchronous Job and Queue Result IDOR](#page-61-asynchronous-job-and-queue-result-idor)
- [Page 62: Audit Log, Activity Feed, and Notification Data Exposure](#page-62-audit-log-activity-feed-and-notification-data-exposure)
- [Page 63: Feature Flags, Plans, Trials, and Entitlement Bypass](#page-63-feature-flags-plans-trials-and-entitlement-bypass)
- [Page 64: Hidden Parameters and Server-Side Trust of Client State](#page-64-hidden-parameters-and-server-side-trust-of-client-state)
- [Page 65: Error Handling With Sensitive Data or Control Impact](#page-65-error-handling-with-sensitive-data-or-control-impact)
- [Page 66: Daily Manual Hunting Workflow: 90-Minute Focus Blocks](#page-66-daily-manual-hunting-workflow-90-minute-focus-blocks)
- [Page 67: Feature-by-Feature Manual Test Matrix](#page-67-feature-by-feature-manual-test-matrix)
- [Page 68: Safe Payload and Marker Strategy](#page-68-safe-payload-and-marker-strategy)
- [Page 69: Writing High-Signal Bug Bounty Reports](#page-69-writing-high-signal-bug-bounty-reports)
- [Page 70: Retesting and Chaining Method](#page-70-retesting-and-chaining-method)
- [Page 71: Manual Notes Template for Each Target](#page-71-manual-notes-template-for-each-target)
- [Page 72: Quick Decision Tree: What Should I Test Next?](#page-72-quick-decision-tree-what-should-i-test-next)
- [Page 73: Final Pre-Submission Checklist](#page-73-final-pre-submission-checklist)
- [Page 74: Sources and Further Practice](#page-74-sources-and-further-practice)


<div style="page-break-after: always;"></div>

## Page 1: Operating Rules, Authorization, and Safety Boundaries

### Non-negotiable rules

- Test only targets explicitly listed in the program scope. If scope says `*.example.com` but excludes `admin.example.com`, do not test the excluded host.
- Use only accounts you own or accounts explicitly issued by the program. For multi-tenant tests, create two separate tenants/orgs when permitted.
- Never access, download, modify, or disclose real user data. If an IDOR shows another user’s record, stop after proving with your own Account B.
- Avoid destructive proof: no deletion of production objects unless the object is yours and deletion is reversible or allowed.
- Avoid noisy automation unless program rules allow it. “Manual first” means careful request analysis, not denial-of-service testing.
- Do not persist XSS payloads where unrelated users or employees may trigger them unless the program explicitly permits stored XSS testing and you can isolate the payload.
- Do not attempt phishing, social engineering, credential stuffing, MFA bombing, password spraying, malware upload, persistence, post-exploitation, or lateral movement.
- For SSRF, command injection, SQL injection, XXE, and file upload tests, use the smallest possible proof. Prefer harmless callbacks or response differences over data extraction.

### Safe proof standard

A report is stronger when the evidence shows:

- The exact vulnerable request.
- The exact authorization state used.
- The exact object/user/tenant that should not be accessible.
- The actual unauthorized response or side effect.
- Why the exposed data or action matters.
- Why the behavior violates program expectations or security boundaries.

### Stop conditions

Stop testing and report immediately when you demonstrate any of the following with controlled data:

- Account A can read or change Account B’s private data.
- A low-privilege user can perform an admin-only action.
- A guest or unauthenticated user can access authenticated data.
- A token can be replayed, forged, reused after logout, or used after expiry.
- A workflow can be completed without required payment, approval, verification, or consent.
- An upload can become executable or overwrite/serve dangerous content.
- A server makes an outbound request to your collaborator domain from a user-controlled URL.


<div style="page-break-after: always;"></div>

## Page 2: Impact-First Bug Selection: Avoid Informative-Only Traps

The easiest way to waste a day is to report findings that are technically true but security-light. Missing headers, version banners, generic verbose errors, low-risk clickjacking, SPF warnings, open CORS without credentials, directory listing of public assets, and weak TLS ciphers are frequently out of scope or informative unless you connect them to real impact.

### Reportability filter

Before spending time, ask:

1. **Can I cross a trust boundary?** Example: user-to-user, user-to-admin, tenant-to-tenant, unauthenticated-to-authenticated, client-to-server, external-to-internal.
2. **Can I access or alter protected data?** Private profile, invoices, tickets, messages, reports, PII, secrets, auth tokens, internal files, payment details.
3. **Can I perform a protected action?** Invite user, change role, change email/password, issue refund, redeem coupon, approve workflow, disable MFA, export data.
4. **Can I bypass a security control?** MFA, email verification, rate limits, CSRF protection, OAuth redirect validation, file type validation, signature verification.
5. **Can I chain a low bug into a high bug?** Open redirect + OAuth token leak, HTML injection + password reset token leak, CORS + credentials + sensitive endpoint, IDOR + password reset token exposure.

### Usually low-value unless chained

- Security headers missing with no exploit path.
- Clickjacking on a page with no state-changing or sensitive action.
- Reflected HTML injection that cannot execute script or leak data.
- Open redirect with no OAuth/SAML/token/cookie/referrer impact.
- Public directory listing of non-sensitive static files.
- Username enumeration where program excludes it or where there is no practical abuse path.
- Rate limit absence on low-risk endpoints without account lockout, OTP, password reset, cost, or abuse impact.
- “Outdated library” with no exploitable version-specific vulnerability or reachable code path.

### Preferred targets

Prioritize features where a business action happens: login, signup, password reset, MFA, invite flows, billing, subscriptions, exports, admin panels, APIs, file uploads, webhooks, integrations, OAuth/SSO, report generation, search, importers, and anything with object IDs.


<div style="page-break-after: always;"></div>

## Page 3: Bugcrowd VRT-Aligned Severity Thinking

Bugcrowd’s Vulnerability Rating Taxonomy is a baseline priority guide, not a magic severity oracle. The same class can move up or down based on the asset, data sensitivity, exploit reliability, authentication requirements, user interaction, and business context. IDOR/BOLA is the classic example: reading a public profile might be low, changing another user’s billing address might be high, and account takeover may be critical.

### Practical P-level intuition

- **P1 / Critical:** Full account takeover at scale, unauthenticated RCE, mass sensitive data compromise, tenant-wide admin takeover, payment-system compromise, critical cloud credential exposure.
- **P2 / High:** Authenticated privilege escalation, access to highly sensitive private data, write/delete IDOR on important objects, OAuth token theft, SSRF with sensitive internal access, serious SQL injection.
- **P3 / Medium:** Limited but real unauthorized access, stored XSS affecting normal users, CSRF on meaningful actions, bypasses requiring specific conditions, lower-sensitivity tenant/user data exposure.
- **P4 / Low:** Limited exposure or limited-impact bypass, self-XSS only when it can be chained, clickjacking with minor state change, open redirect with realistic but limited impact.
- **P5 / Informational:** Best-practice gaps without demonstrated impact.

### Severity inflation mistakes

Do not claim “critical” because a class name sounds scary. A stored XSS in an admin-only internal note could be high if an admin regularly views it; it could be low if it is only self-triggered and cannot reach privileged users. A CORS misconfiguration is not a vulnerability by itself if it cannot be used with credentials or tokens to read sensitive data. A reflected parameter in JavaScript is not XSS until you prove execution in the correct context.

### How to frame impact

Use concrete language:

- “A member of Tenant A can download invoices belonging to Tenant B.”
- “A read-only user can add administrators to the organization.”
- “A password reset token remains valid after email change and can reset the new account.”
- “The OAuth redirect can be changed to an attacker-controlled path on the whitelisted domain, allowing code leakage via an open redirect gadget.”
- “The API accepts `role=admin` in a profile update request and applies it server-side.”


<div style="page-break-after: always;"></div>

## Page 4: Manual Testing Environment and Tool Stack

### Core manual tools

- **Burp Suite Community/Professional**: HTTP history, Repeater, Comparer, Intruder for tiny controlled payload sets, Logger, Decoder, Collaborator if available.
- **OWASP ZAP**: proxying, passive analysis, manual request replay.
- **Browser DevTools**: network tab, storage, service workers, local/session storage, source maps, WebSocket frames.
- **curl/httpie**: reproducible one-line requests in reports.
- **jq**: compare JSON fields, extract IDs, diff API responses.
- **jwt.io or Burp JWT Editor**: inspect JWT header/payload and test verification issues safely.
- **Interactsh/Burp Collaborator**: out-of-band callback detection for SSRF/XXE/blind injection, where permitted.
- **Postman/Insomnia**: API collections, auth contexts, environment variables for Account A/B.
- **ffuf/dirsearch**: light content discovery only when rules permit; keep rate low and use scoped wordlists.
- **Param Miner / Arjun**: discover hidden parameters, but verify manually.
- **GraphQL Voyager/Altair/InQL**: introspection and query building where GraphQL is in scope.

### Test identity setup

Create a small identity matrix:

| Identity | Role | Tenant | Purpose |
|---|---:|---:|---|
| A1 | owner/admin | Tenant A | baseline privileged actions |
| A2 | normal member | Tenant A | vertical privilege tests |
| B1 | owner/admin | Tenant B | cross-tenant comparison |
| B2 | normal member | Tenant B | IDOR/BOLA target object owner |
| G | guest/unauth | none | public/auth boundary tests |

### Proxy hygiene

- Disable browser extensions that pollute traffic.
- Use separate browser profiles for A and B accounts.
- Label tabs and proxy sessions clearly.
- Export key requests as `.http` snippets for report reproducibility.
- Use unique test strings: `bbtest-YYYYMMDD-random-purpose`.
- Save screenshots only of your own test data.


<div style="page-break-after: always;"></div>

## Page 5: The Universal Two-Account Differential Method

Most high-yield manual findings come from comparing Account A and Account B. The goal is not to guess hidden secrets; it is to check whether the server enforces the access control and workflow rules that the UI implies.

### Step-by-step loop

1. Log in as Account A. Create an object: profile field, project, invoice, ticket, document, API key, address, order, integration, webhook, saved search, report, file.
2. Capture the create, read, update, delete, list, export, share, invite, and archive requests for that object.
3. Log in as Account B in a different browser profile. Create the same kind of object.
4. Replace A’s object ID with B’s object ID in A’s requests and vice versa.
5. Repeat across methods: `GET`, `POST`, `PUT`, `PATCH`, `DELETE`, and sometimes `HEAD`.
6. Repeat across representations: URL path, query string, JSON body, headers, cookies, GraphQL variables, multipart form fields.
7. Compare responses. A `403` is good defense; a `200` with sensitive fields is a finding; a `204` on update/delete may be a finding even if response body is empty.
8. Confirm side effect in UI using the object owner account.

### What to mutate

- Sequential IDs: `123`, `124`, `125`.
- UUIDs: copy from B’s object.
- Slugs/usernames: `/users/alice`, `/users/bob`.
- Tenant/org IDs: `org_id`, `workspaceId`, `account_id`, `company`, `team`.
- Nested IDs: `/orgs/{org}/projects/{project}/files/{file}`.
- Hidden body fields: `ownerId`, `createdBy`, `user_id`, `role`, `permissions`, `isAdmin`.
- Headers: `X-Org-ID`, `X-Account-ID`, `X-User-ID`, `X-Tenant`, `X-Forwarded-User`.

### Evidence rule

Never use real victims. If you can show A reading B’s private test invoice with a unique marker you created, that is enough.


<div style="page-break-after: always;"></div>

## Page 6: Recon for Manual Testing Without Becoming Noise

Recon should feed manual testing. A huge list of subdomains is less useful than five endpoints with object IDs, exports, uploads, or admin-only verbs. Keep a notebook with assets, technologies, authentication models, API routes, roles, tenants, and business flows.

### Low-noise recon checklist

- Read the program policy: scope, exclusions, test accounts, rate limits, forbidden bug classes, safe harbor, disclosure rules.
- Identify main apps: marketing site, app dashboard, API, admin console, mobile API, docs, status, support portal, developer portal.
- Capture JavaScript bundles and look for API route names, GraphQL operations, feature flags, role strings, environment names, upload endpoints, webhook paths, OAuth client IDs, and source maps.
- Build a route map from browser traffic rather than only from wordlists.
- Find old API versions referenced in JavaScript, mobile apps, documentation, SDKs, changelogs, or OpenAPI specs.
- Look for domains that represent trust boundaries: `admin`, `api`, `auth`, `sso`, `partners`, `billing`, `internal`, `staging`, `sandbox`, `dev`, `files`, `uploads`.
- Check if the app exposes OpenAPI/Swagger/GraphQL schemas in scoped assets.
- Create your identity matrix before deep testing.

### Avoid recon rabbit holes

- Do not mass scan every IP unless the program permits it.
- Do not report a subdomain merely because it exists.
- Do not report a login panel unless default credentials, bypass, or sensitive exposure is proven and allowed.
- Do not report technology versions without a reachable exploit path.

### Recon output format

Maintain a table:

| Asset | Auth? | Important endpoints | Roles | Object IDs | Notes |
|---|---|---|---|---|---|
| `app.example.com` | yes | `/api/projects`, `/api/billing` | owner/member | projectId, invoiceId | start with BOLA |


<div style="page-break-after: always;"></div>

## Page 7: Reportability Matrix: Informative vs Valid

Use this matrix before reporting.

| Finding idea | Usually informative when... | Usually valid when... |
|---|---|---|
| Missing security header | No exploit path | Combined with XSS/clickjacking/token leakage impact |
| CORS wildcard | No credentials/tokens exposed | Attacker origin can read sensitive authenticated response |
| Open redirect | Only redirects user | Leaks OAuth/SAML/token/code, bypasses allowlist, or enables account takeover chain |
| Username enumeration | Login says user exists | Can abuse password reset, OTP, invitation, cost, or targeted security impact |
| Rate limit missing | Low-risk endpoint | Password reset/OTP/login/invite/export/costly action can be abused |
| Directory listing | Static public files | Sensitive backups, configs, logs, keys, exports, private uploads exposed |
| Clickjacking | Static page | Meaningful state-changing action can be triggered without user awareness |
| Reflected HTML injection | No script/data leak | Can execute JS, steal token/code, alter trusted page, or chain with OAuth |
| Source map exposed | Only public code | Secrets, private endpoints, hidden admin functions, or tokens exposed |
| Old library | Version only | Confirmed vulnerable version + reachable feature + safe PoC |

### Triage-friendly phrasing

Weak: “The app is missing HSTS.”  
Strong: “Because the session cookie lacks Secure and the app accepts HTTP on the same host, a network attacker can force a request that leaks the session ID. Evidence: controlled local test and captured cookie over HTTP.”

Weak: “There is an open redirect.”  
Strong: “The OAuth `redirect_uri` allowlist can be bypassed through `/redirect?next=...`, causing the authorization code to be sent to an attacker-controlled endpoint.”


<div style="page-break-after: always;"></div>

## Page 8: Unauthenticated Access Boundary Checks

**VRT alignment:** Broken Access Control / Server Security Misconfiguration / Sensitive Data Exposure  
**Best auth state:** Unauthenticated and authenticated comparison

### Why this is worth testing

Many applications hide features in the UI but forget to enforce login on APIs, exported files, static object URLs, pre-signed links, or old routes.

### Manual test procedure

1. Log out and replay authenticated GET requests.
2. Remove cookies and Authorization headers one at a time.
3. Try direct URLs for downloaded reports, invoices, attachments, thumbnails, private images, and exports.
4. Check whether `HEAD` or `OPTIONS` reveals private metadata.
5. Test old API versions and mobile routes found in JavaScript or app traffic.


### Tools that help without replacing manual work

Burp Repeater, browser private window, curl, jq, DevTools, small route map.

### Evidence that usually proves impact

Private object readable without authentication, private file accessible from direct link, export token reusable by anyone, unauthenticated access to account settings or internal data.

### Common false positives / informative-only cases

Do not report public marketing assets, public images, robots.txt entries, or unauthenticated pages intended to be public.

### Report skeleton

```text
Title: Unauthenticated Access Boundary Checks allows [unauthorized action/data] in [asset/feature]
Asset: https://target.example/path
Prerequisites: Account A [role], Account B [role], both controlled by researcher
Steps:
1. Create controlled object/data as Account B.
2. Capture the vulnerable request as Account A.
3. Modify [exact field] from [A value] to [B value].
4. Send the request and observe [response/side effect].
5. Confirm in Account B UI that [unauthorized access/change] occurred.
Impact: [concrete business/security impact]
Suggested fix: Enforce server-side authorization for [object/function/property] on every request.
```

### Fast checklist

- [ ] Tested logged out, low role, high role, same tenant, different tenant where relevant.
- [ ] Changed one variable at a time.
- [ ] Used only controlled accounts/data.
- [ ] Captured before/after evidence.
- [ ] Explained why this is more than informative.


<div style="page-break-after: always;"></div>

## Page 9: IDOR / BOLA: Read Another User or Tenant Object

**VRT alignment:** Broken Access Control; severity varies heavily by data sensitivity and reachability  
**Best auth state:** Usually authenticated with two controlled accounts

### Why this is worth testing

Object IDs appear everywhere in APIs and are often trusted by the server. This is one of the most consistently productive manual bug bounty classes.

### Manual test procedure

1. Create object as Account B with unique marker.
2. Capture Account A request for same endpoint.
3. Replace Account A object ID with Account B object ID.
4. Check path, query, body, headers, GraphQL variables, and nested objects.
5. Confirm that the response includes B-only private data.


### Tools that help without replacing manual work

Burp Repeater/Comparer, Logger, jq, Postman environments for A/B tokens.

### Evidence that usually proves impact

A user can read another user’s invoice, ticket, file, address, private note, API key metadata, messages, project data, or tenant resources.

### Common false positives / informative-only cases

Do not enumerate real IDs. Use only your own accounts. Do not claim high severity for public data.

### Report skeleton

```text
Title: IDOR / BOLA: Read Another User or Tenant Object allows [unauthorized action/data] in [asset/feature]
Asset: https://target.example/path
Prerequisites: Account A [role], Account B [role], both controlled by researcher
Steps:
1. Create controlled object/data as Account B.
2. Capture the vulnerable request as Account A.
3. Modify [exact field] from [A value] to [B value].
4. Send the request and observe [response/side effect].
5. Confirm in Account B UI that [unauthorized access/change] occurred.
Impact: [concrete business/security impact]
Suggested fix: Enforce server-side authorization for [object/function/property] on every request.
```

### Fast checklist

- [ ] Tested logged out, low role, high role, same tenant, different tenant where relevant.
- [ ] Changed one variable at a time.
- [ ] Used only controlled accounts/data.
- [ ] Captured before/after evidence.
- [ ] Explained why this is more than informative.


<div style="page-break-after: always;"></div>

## Page 10: IDOR / BOLA: Write, Delete, or State-Change Another Object

**VRT alignment:** Broken Access Control; often higher than read-only IDOR when critical objects are altered  
**Best auth state:** Authenticated with two controlled accounts

### Why this is worth testing

Even when reads are protected, update/delete endpoints often miss object-level checks.

### Manual test procedure

1. Create disposable object in Account B.
2. Capture update/delete/archive/share request from Account A for A-owned object.
3. Swap B-owned ID into Account A request.
4. Use harmless changes like title=`bbtest-owned-by-a` instead of destructive content.
5. Verify in Account B UI that state changed.


### Tools that help without replacing manual work

Burp Repeater, Comparer, browser profiles, curl reproduction.

### Evidence that usually proves impact

Unauthorized modification or deletion of another user’s project, file, payment method nickname, invoice metadata, team settings, webhook, or support ticket.

### Common false positives / informative-only cases

Do not delete production objects you cannot restore. Avoid testing against real users.

### Report skeleton

```text
Title: IDOR / BOLA: Write, Delete, or State-Change Another Object allows [unauthorized action/data] in [asset/feature]
Asset: https://target.example/path
Prerequisites: Account A [role], Account B [role], both controlled by researcher
Steps:
1. Create controlled object/data as Account B.
2. Capture the vulnerable request as Account A.
3. Modify [exact field] from [A value] to [B value].
4. Send the request and observe [response/side effect].
5. Confirm in Account B UI that [unauthorized access/change] occurred.
Impact: [concrete business/security impact]
Suggested fix: Enforce server-side authorization for [object/function/property] on every request.
```

### Fast checklist

- [ ] Tested logged out, low role, high role, same tenant, different tenant where relevant.
- [ ] Changed one variable at a time.
- [ ] Used only controlled accounts/data.
- [ ] Captured before/after evidence.
- [ ] Explained why this is more than informative.


<div style="page-break-after: always;"></div>

## Page 11: Broken Function Level Authorization: User Calls Admin Endpoint

**VRT alignment:** Broken Access Control / Privilege Escalation  
**Best auth state:** Authenticated low-privilege vs high-privilege comparison

### Why this is worth testing

The UI hides admin buttons, but the server may still accept the request from normal users.

### Manual test procedure

1. Perform action as admin and capture request.
2. Replay request with normal member token.
3. Try direct route, method override, JSON body role fields, and admin GraphQL mutations.
4. Check side effect in admin UI.
5. Test list/export/admin search endpoints too, not only mutations.


### Tools that help without replacing manual work

Burp Repeater, role matrix, browser profiles, GraphQL client.

### Evidence that usually proves impact

Normal member can invite admins, export tenant data, change billing, change roles, disable security settings, approve requests, or access admin-only dashboards.

### Common false positives / informative-only cases

Do not report access to a harmless hidden page without protected data or action.

### Report skeleton

```text
Title: Broken Function Level Authorization: User Calls Admin Endpoint allows [unauthorized action/data] in [asset/feature]
Asset: https://target.example/path
Prerequisites: Account A [role], Account B [role], both controlled by researcher
Steps:
1. Create controlled object/data as Account B.
2. Capture the vulnerable request as Account A.
3. Modify [exact field] from [A value] to [B value].
4. Send the request and observe [response/side effect].
5. Confirm in Account B UI that [unauthorized access/change] occurred.
Impact: [concrete business/security impact]
Suggested fix: Enforce server-side authorization for [object/function/property] on every request.
```

### Fast checklist

- [ ] Tested logged out, low role, high role, same tenant, different tenant where relevant.
- [ ] Changed one variable at a time.
- [ ] Used only controlled accounts/data.
- [ ] Captured before/after evidence.
- [ ] Explained why this is more than informative.


<div style="page-break-after: always;"></div>

## Page 12: Broken Object Property Level Authorization / Mass Assignment

**VRT alignment:** Broken Access Control / API authorization  
**Best auth state:** Authenticated; compare UI fields to API fields

### Why this is worth testing

APIs sometimes accept fields that the UI never exposes, such as role, plan, balance, verified, owner, or permission flags.

### Manual test procedure

1. Capture profile or object update request.
2. Add hidden fields inferred from response: `role`, `isAdmin`, `plan`, `verified`, `ownerId`, `permissions`, `price`, `creditBalance`.
3. Try nested objects: `user: { role: "admin" }`.
4. Try `PATCH` and `PUT` differences.
5. Verify whether server stores unauthorized field.


### Tools that help without replacing manual work

Burp Repeater, JSON beautifier, jq, API schema/OpenAPI if exposed.

### Evidence that usually proves impact

User elevates role, changes plan, marks email verified, changes object owner, modifies price, bypasses approval, or exposes hidden sensitive fields.

### Common false positives / informative-only cases

Do not report a field merely being echoed if it is not stored, trusted, or security-relevant.

### Report skeleton

```text
Title: Broken Object Property Level Authorization / Mass Assignment allows [unauthorized action/data] in [asset/feature]
Asset: https://target.example/path
Prerequisites: Account A [role], Account B [role], both controlled by researcher
Steps:
1. Create controlled object/data as Account B.
2. Capture the vulnerable request as Account A.
3. Modify [exact field] from [A value] to [B value].
4. Send the request and observe [response/side effect].
5. Confirm in Account B UI that [unauthorized access/change] occurred.
Impact: [concrete business/security impact]
Suggested fix: Enforce server-side authorization for [object/function/property] on every request.
```

### Fast checklist

- [ ] Tested logged out, low role, high role, same tenant, different tenant where relevant.
- [ ] Changed one variable at a time.
- [ ] Used only controlled accounts/data.
- [ ] Captured before/after evidence.
- [ ] Explained why this is more than informative.


<div style="page-break-after: always;"></div>

## Page 13: Multi-Tenant Isolation and Organization Boundary Bugs

**VRT alignment:** Broken Access Control; often high when cross-tenant data is exposed  
**Best auth state:** Authenticated, two tenants/orgs

### Why this is worth testing

SaaS apps frequently mix user IDs and tenant IDs. Bugs happen when the server checks user login but not tenant membership.

### Manual test procedure

1. Create Tenant A and Tenant B.
2. Create same resources in both.
3. Swap tenant/org/workspace/account IDs in every request.
4. Test nested routes where only one of several IDs is validated.
5. Check exports, analytics, billing, audit logs, search, notifications, and webhooks.


### Tools that help without replacing manual work

Burp project with comments, jq, Postman environments, spreadsheet of IDs.

### Evidence that usually proves impact

Tenant A can view Tenant B customers, invoices, projects, files, members, audit logs, API keys, integrations, or analytics.

### Common false positives / informative-only cases

Do not use real tenant IDs. Avoid overclaiming if only public tenant metadata is exposed.

### Report skeleton

```text
Title: Multi-Tenant Isolation and Organization Boundary Bugs allows [unauthorized action/data] in [asset/feature]
Asset: https://target.example/path
Prerequisites: Account A [role], Account B [role], both controlled by researcher
Steps:
1. Create controlled object/data as Account B.
2. Capture the vulnerable request as Account A.
3. Modify [exact field] from [A value] to [B value].
4. Send the request and observe [response/side effect].
5. Confirm in Account B UI that [unauthorized access/change] occurred.
Impact: [concrete business/security impact]
Suggested fix: Enforce server-side authorization for [object/function/property] on every request.
```

### Fast checklist

- [ ] Tested logged out, low role, high role, same tenant, different tenant where relevant.
- [ ] Changed one variable at a time.
- [ ] Used only controlled accounts/data.
- [ ] Captured before/after evidence.
- [ ] Explained why this is more than informative.


<div style="page-break-after: always;"></div>

## Page 14: Invite, Team, and Role Workflow Flaws

**VRT alignment:** Broken Access Control / Business Logic  
**Best auth state:** Authenticated; owner/member/invitee states

### Why this is worth testing

Invitation flows combine email, role, token, tenant, expiration, and acceptance state. Small mistakes can become privilege escalation.

### Manual test procedure

1. Invite Account B as low role, intercept invite request, change role to admin.
2. Accept invite after removal, expiry, email change, or tenant switch.
3. Reuse invite token across accounts.
4. Change invite email in request body after token is issued.
5. Test if a removed user can still use old invitation or session.


### Tools that help without replacing manual work

Burp Repeater, email inbox for test accounts, browser profiles.

### Evidence that usually proves impact

Invitee becomes admin, removed user rejoins, invite token grants wrong tenant access, or user accepts invitation intended for another email.

### Common false positives / informative-only cases

Do not target third-party email addresses. Use your own controlled mailboxes.

### Report skeleton

```text
Title: Invite, Team, and Role Workflow Flaws allows [unauthorized action/data] in [asset/feature]
Asset: https://target.example/path
Prerequisites: Account A [role], Account B [role], both controlled by researcher
Steps:
1. Create controlled object/data as Account B.
2. Capture the vulnerable request as Account A.
3. Modify [exact field] from [A value] to [B value].
4. Send the request and observe [response/side effect].
5. Confirm in Account B UI that [unauthorized access/change] occurred.
Impact: [concrete business/security impact]
Suggested fix: Enforce server-side authorization for [object/function/property] on every request.
```

### Fast checklist

- [ ] Tested logged out, low role, high role, same tenant, different tenant where relevant.
- [ ] Changed one variable at a time.
- [ ] Used only controlled accounts/data.
- [ ] Captured before/after evidence.
- [ ] Explained why this is more than informative.


<div style="page-break-after: always;"></div>

## Page 15: Account Registration and Email Verification Bypass

**VRT alignment:** Authentication / Business Logic / Access Control  
**Best auth state:** Unauthenticated signup plus authenticated pending account

### Why this is worth testing

Verification is often a UI gate, while APIs may still accept actions from unverified accounts.

### Manual test procedure

1. Create unverified account and capture available APIs.
2. Try direct access to protected actions before email verification.
3. Change email after token issuance and use old token.
4. Replay verification token twice or from another account.
5. Try case/plus/dot variations if program allows.


### Tools that help without replacing manual work

Burp, temporary test email aliases you control, browser profiles.

### Evidence that usually proves impact

Unverified accounts can access restricted features, claim another email, bypass tenant invite verification, or trigger account takeover chains.

### Common false positives / informative-only cases

Do not report cosmetic access to a welcome page unless restricted actions/data are available.

### Report skeleton

```text
Title: Account Registration and Email Verification Bypass allows [unauthorized action/data] in [asset/feature]
Asset: https://target.example/path
Prerequisites: Account A [role], Account B [role], both controlled by researcher
Steps:
1. Create controlled object/data as Account B.
2. Capture the vulnerable request as Account A.
3. Modify [exact field] from [A value] to [B value].
4. Send the request and observe [response/side effect].
5. Confirm in Account B UI that [unauthorized access/change] occurred.
Impact: [concrete business/security impact]
Suggested fix: Enforce server-side authorization for [object/function/property] on every request.
```

### Fast checklist

- [ ] Tested logged out, low role, high role, same tenant, different tenant where relevant.
- [ ] Changed one variable at a time.
- [ ] Used only controlled accounts/data.
- [ ] Captured before/after evidence.
- [ ] Explained why this is more than informative.


<div style="page-break-after: always;"></div>

## Page 16: Password Reset Token Weakness and Account Takeover Paths

**VRT alignment:** Authentication / Sensitive Data Exposure / Account Takeover  
**Best auth state:** Unauthenticated reset initiation, authenticated account state changes

### Why this is worth testing

Password reset sits directly on the account takeover path and is highly manual-testable.

### Manual test procedure

1. Request reset for Account A and inspect token length, location, reuse, expiry, and binding.
2. Use token once, then try reuse.
3. Request multiple tokens and see whether old tokens remain valid.
4. Change email/password/session state and test whether reset token remains valid.
5. Try token from Account A on Account B endpoint only with your accounts.


### Tools that help without replacing manual work

Burp Repeater, mailboxes you control, timestamp notebook, Decoder.

### Evidence that usually proves impact

Reusable/non-expiring token, token not bound to user, reset works after email change, old tokens remain valid, reset link leaks via Referer or redirect.

### Common false positives / informative-only cases

Do not brute force tokens. Do not request resets for real users. Username enumeration alone may be low unless abuse path exists.

### Report skeleton

```text
Title: Password Reset Token Weakness and Account Takeover Paths allows [unauthorized action/data] in [asset/feature]
Asset: https://target.example/path
Prerequisites: Account A [role], Account B [role], both controlled by researcher
Steps:
1. Create controlled object/data as Account B.
2. Capture the vulnerable request as Account A.
3. Modify [exact field] from [A value] to [B value].
4. Send the request and observe [response/side effect].
5. Confirm in Account B UI that [unauthorized access/change] occurred.
Impact: [concrete business/security impact]
Suggested fix: Enforce server-side authorization for [object/function/property] on every request.
```

### Fast checklist

- [ ] Tested logged out, low role, high role, same tenant, different tenant where relevant.
- [ ] Changed one variable at a time.
- [ ] Used only controlled accounts/data.
- [ ] Captured before/after evidence.
- [ ] Explained why this is more than informative.


<div style="page-break-after: always;"></div>

## Page 17: Change Email / Change Password Authorization Gaps

**VRT alignment:** Authentication / Session Management / Business Logic  
**Best auth state:** Authenticated

### Why this is worth testing

Account security actions must require fresh authentication and proper token/session invalidation.

### Manual test procedure

1. Change password and see whether old sessions remain valid.
2. Change email and test whether verification is required before login/reset moves to new email.
3. Replay change request without current password or CSRF token.
4. Try changing another account email through IDOR fields.
5. Test whether password reset tokens survive password changes.


### Tools that help without replacing manual work

Burp, two browsers, controlled email accounts.

### Evidence that usually proves impact

Account takeover, session persistence after password change, unauthorized email change, bypass of current password requirement.

### Common false positives / informative-only cases

Do not report missing “current password” if the program/app design clearly uses strong fresh-session reauth elsewhere and no bypass exists.

### Report skeleton

```text
Title: Change Email / Change Password Authorization Gaps allows [unauthorized action/data] in [asset/feature]
Asset: https://target.example/path
Prerequisites: Account A [role], Account B [role], both controlled by researcher
Steps:
1. Create controlled object/data as Account B.
2. Capture the vulnerable request as Account A.
3. Modify [exact field] from [A value] to [B value].
4. Send the request and observe [response/side effect].
5. Confirm in Account B UI that [unauthorized access/change] occurred.
Impact: [concrete business/security impact]
Suggested fix: Enforce server-side authorization for [object/function/property] on every request.
```

### Fast checklist

- [ ] Tested logged out, low role, high role, same tenant, different tenant where relevant.
- [ ] Changed one variable at a time.
- [ ] Used only controlled accounts/data.
- [ ] Captured before/after evidence.
- [ ] Explained why this is more than informative.


<div style="page-break-after: always;"></div>

## Page 18: MFA Enrollment, Removal, Recovery, and Step-Up Bypass

**VRT alignment:** Authentication / Business Logic / Access Control  
**Best auth state:** Authenticated; MFA-enabled test account

### Why this is worth testing

MFA is often bolted onto existing auth flows; edge cases in recovery and session transitions are common.

### Manual test procedure

1. Enable MFA on Account A and record pre-MFA session behavior.
2. Try sensitive endpoints with old session before completing MFA.
3. Try removing MFA without password or MFA proof.
4. Test recovery codes for reuse and binding.
5. Test remember-device tokens after password change/logout.


### Tools that help without replacing manual work

Authenticator app, Burp, two browser profiles, timestamped notes.

### Evidence that usually proves impact

MFA can be removed, bypassed, or recovery codes reused; sensitive actions accessible before step-up; remembered devices survive account compromise cleanup.

### Common false positives / informative-only cases

Do not brute force OTPs. Do not perform MFA bombing or notification spam.

### Report skeleton

```text
Title: MFA Enrollment, Removal, Recovery, and Step-Up Bypass allows [unauthorized action/data] in [asset/feature]
Asset: https://target.example/path
Prerequisites: Account A [role], Account B [role], both controlled by researcher
Steps:
1. Create controlled object/data as Account B.
2. Capture the vulnerable request as Account A.
3. Modify [exact field] from [A value] to [B value].
4. Send the request and observe [response/side effect].
5. Confirm in Account B UI that [unauthorized access/change] occurred.
Impact: [concrete business/security impact]
Suggested fix: Enforce server-side authorization for [object/function/property] on every request.
```

### Fast checklist

- [ ] Tested logged out, low role, high role, same tenant, different tenant where relevant.
- [ ] Changed one variable at a time.
- [ ] Used only controlled accounts/data.
- [ ] Captured before/after evidence.
- [ ] Explained why this is more than informative.


<div style="page-break-after: always;"></div>

## Page 19: Session Fixation, Logout, Cookie, and Token Lifecycle Bugs

**VRT alignment:** Session Management / Authentication  
**Best auth state:** Authenticated and unauthenticated transition testing

### Why this is worth testing

A valid session is the core security boundary. Weak regeneration, logout, and token invalidation produce real impact.

### Manual test procedure

1. Capture session cookie before login and after login; check whether value changes.
2. Logout and replay old authenticated request.
3. Change password and replay old session/API token.
4. Check session token in URL, localStorage, logs, or Referer-prone places.
5. Test cookie flags only when tied to exploitability.


### Tools that help without replacing manual work

Burp Cookie Jar, browser storage inspector, curl, jwt decoder.

### Evidence that usually proves impact

Session remains valid after logout/password change, session fixation across login, token in URL leaks through referrer, privileged session not invalidated after role removal.

### Common false positives / informative-only cases

Missing HttpOnly/Secure/SameSite alone is often low/informative unless you show realistic theft or action impact.

### Report skeleton

```text
Title: Session Fixation, Logout, Cookie, and Token Lifecycle Bugs allows [unauthorized action/data] in [asset/feature]
Asset: https://target.example/path
Prerequisites: Account A [role], Account B [role], both controlled by researcher
Steps:
1. Create controlled object/data as Account B.
2. Capture the vulnerable request as Account A.
3. Modify [exact field] from [A value] to [B value].
4. Send the request and observe [response/side effect].
5. Confirm in Account B UI that [unauthorized access/change] occurred.
Impact: [concrete business/security impact]
Suggested fix: Enforce server-side authorization for [object/function/property] on every request.
```

### Fast checklist

- [ ] Tested logged out, low role, high role, same tenant, different tenant where relevant.
- [ ] Changed one variable at a time.
- [ ] Used only controlled accounts/data.
- [ ] Captured before/after evidence.
- [ ] Explained why this is more than informative.


<div style="page-break-after: always;"></div>

## Page 20: OAuth / OIDC Redirect, State, Scope, and Account Linking Bugs

**VRT alignment:** Authentication / Account Takeover / Sensitive Data Exposure  
**Best auth state:** Unauthenticated login plus authenticated OAuth-linked account

### Why this is worth testing

OAuth is common and implementation errors can leak authorization codes/tokens or bind identities incorrectly.

### Manual test procedure

1. Map authorize URL parameters: `client_id`, `redirect_uri`, `response_type`, `scope`, `state`, `nonce`, `code_challenge`.
2. Try redirect URI path traversal, subdomain variations, encoded characters, and whitelisted open redirect gadgets.
3. Check missing or reusable `state` causing login CSRF.
4. Test account linking: can attacker link their provider account to victim local account?
5. Check whether email_verified and issuer are validated.


### Tools that help without replacing manual work

Burp Repeater, browser devtools, OAuth debugger, controlled OAuth test accounts.

### Evidence that usually proves impact

Authorization code/token leak, login CSRF, account takeover via email trust, scope escalation, token substitution, misbound identities.

### Common false positives / informative-only cases

Do not use real social accounts of others. Open redirect alone is weak unless it leaks OAuth artifacts or chains.

### Report skeleton

```text
Title: OAuth / OIDC Redirect, State, Scope, and Account Linking Bugs allows [unauthorized action/data] in [asset/feature]
Asset: https://target.example/path
Prerequisites: Account A [role], Account B [role], both controlled by researcher
Steps:
1. Create controlled object/data as Account B.
2. Capture the vulnerable request as Account A.
3. Modify [exact field] from [A value] to [B value].
4. Send the request and observe [response/side effect].
5. Confirm in Account B UI that [unauthorized access/change] occurred.
Impact: [concrete business/security impact]
Suggested fix: Enforce server-side authorization for [object/function/property] on every request.
```

### Fast checklist

- [ ] Tested logged out, low role, high role, same tenant, different tenant where relevant.
- [ ] Changed one variable at a time.
- [ ] Used only controlled accounts/data.
- [ ] Captured before/after evidence.
- [ ] Explained why this is more than informative.


<div style="page-break-after: always;"></div>

## Page 21: JWT Claim Tampering and Signature Verification Flaws

**VRT alignment:** Authentication / Access Control / Cryptographic Failure  
**Best auth state:** Authenticated; token-bearing APIs

### Why this is worth testing

JWTs expose claims client-side. If verification is weak, changing `sub`, `role`, `tenant`, or `exp` can bypass authz.

### Manual test procedure

1. Decode token and identify claims used by app.
2. Change non-sensitive claim and send; expect rejection.
3. Try `alg` none only in safe controlled way and stop if accepted.
4. Check whether expired tokens are accepted.
5. Check `kid`, `jku`, `jwk` header behavior only with non-destructive controlled keys/callbacks.


### Tools that help without replacing manual work

Burp JWT Editor, jwt.io for decoding, Repeater, controlled test keys where allowed.

### Evidence that usually proves impact

Impersonation, role escalation, tenant switch, acceptance of unsigned/expired/self-signed tokens.

### Common false positives / informative-only cases

Do not brute force JWT secrets on production unless explicitly allowed. Reading base64 JWT claims is not a bug by itself.

### Report skeleton

```text
Title: JWT Claim Tampering and Signature Verification Flaws allows [unauthorized action/data] in [asset/feature]
Asset: https://target.example/path
Prerequisites: Account A [role], Account B [role], both controlled by researcher
Steps:
1. Create controlled object/data as Account B.
2. Capture the vulnerable request as Account A.
3. Modify [exact field] from [A value] to [B value].
4. Send the request and observe [response/side effect].
5. Confirm in Account B UI that [unauthorized access/change] occurred.
Impact: [concrete business/security impact]
Suggested fix: Enforce server-side authorization for [object/function/property] on every request.
```

### Fast checklist

- [ ] Tested logged out, low role, high role, same tenant, different tenant where relevant.
- [ ] Changed one variable at a time.
- [ ] Used only controlled accounts/data.
- [ ] Captured before/after evidence.
- [ ] Explained why this is more than informative.


<div style="page-break-after: always;"></div>

## Page 22: CSRF on Meaningful State-Changing Actions

**VRT alignment:** Cross-Site Request Forgery / Business Logic  
**Best auth state:** Authenticated victim simulation with your own account

### Why this is worth testing

CSRF is reportable when it changes important state and modern browser protections do not stop it.

### Manual test procedure

1. Find state-changing endpoint using cookies for auth.
2. Remove CSRF token and replay.
3. Change method/content-type to see if endpoint accepts simple requests.
4. Build local HTML PoC against your own account.
5. Confirm side effect: email changed, role changed, webhook added, MFA disabled, payment action triggered.


### Tools that help without replacing manual work

Burp CSRF PoC generator, local HTML file, browser profiles.

### Evidence that usually proves impact

Victim can be forced to change email, add attacker webhook, change role, modify security settings, perform transaction, or connect integration.

### Common false positives / informative-only cases

Logout CSRF and harmless preference changes are often low/informative. SameSite may block some PoCs; prove browser-realistic exploitability.

### Report skeleton

```text
Title: CSRF on Meaningful State-Changing Actions allows [unauthorized action/data] in [asset/feature]
Asset: https://target.example/path
Prerequisites: Account A [role], Account B [role], both controlled by researcher
Steps:
1. Create controlled object/data as Account B.
2. Capture the vulnerable request as Account A.
3. Modify [exact field] from [A value] to [B value].
4. Send the request and observe [response/side effect].
5. Confirm in Account B UI that [unauthorized access/change] occurred.
Impact: [concrete business/security impact]
Suggested fix: Enforce server-side authorization for [object/function/property] on every request.
```

### Fast checklist

- [ ] Tested logged out, low role, high role, same tenant, different tenant where relevant.
- [ ] Changed one variable at a time.
- [ ] Used only controlled accounts/data.
- [ ] Captured before/after evidence.
- [ ] Explained why this is more than informative.


<div style="page-break-after: always;"></div>

## Page 23: CORS Misconfiguration With Credentialed Data Theft

**VRT alignment:** Server Security Misconfiguration / Sensitive Data Exposure  
**Best auth state:** Authenticated browser victim simulation

### Why this is worth testing

CORS is only impactful when an attacker-controlled origin can read sensitive authenticated responses.

### Manual test procedure

1. Send request with `Origin: https://attacker.example`.
2. Check `Access-Control-Allow-Origin` reflection and `Access-Control-Allow-Credentials: true`.
3. Host a local PoC page that fetches sensitive endpoint using your own authenticated browser.
4. Check null origin, subdomain regex mistakes, and protocol confusion.
5. Confirm readable sensitive JSON, not just request success.


### Tools that help without replacing manual work

Burp Repeater, local HTML PoC, browser console.

### Evidence that usually proves impact

Attacker site can read profile, API keys, private documents, invoices, or tokens from authenticated user browser.

### Common false positives / informative-only cases

Wildcard ACAO without credentials and no sensitive public data is usually not reportable.

### Report skeleton

```text
Title: CORS Misconfiguration With Credentialed Data Theft allows [unauthorized action/data] in [asset/feature]
Asset: https://target.example/path
Prerequisites: Account A [role], Account B [role], both controlled by researcher
Steps:
1. Create controlled object/data as Account B.
2. Capture the vulnerable request as Account A.
3. Modify [exact field] from [A value] to [B value].
4. Send the request and observe [response/side effect].
5. Confirm in Account B UI that [unauthorized access/change] occurred.
Impact: [concrete business/security impact]
Suggested fix: Enforce server-side authorization for [object/function/property] on every request.
```

### Fast checklist

- [ ] Tested logged out, low role, high role, same tenant, different tenant where relevant.
- [ ] Changed one variable at a time.
- [ ] Used only controlled accounts/data.
- [ ] Captured before/after evidence.
- [ ] Explained why this is more than informative.


<div style="page-break-after: always;"></div>

## Page 24: Reflected XSS With Context-Aware Payloading

**VRT alignment:** Client-Side Injection / Cross-Site Scripting  
**Best auth state:** Both unauthenticated and authenticated pages

### Why this is worth testing

Reflected XSS is easy to test but often duplicates or low impact. Context-aware testing reduces noise.

### Manual test procedure

1. Inject unique marker into every parameter, header-derived field, search box, redirect message, error page.
2. Find reflection context: HTML text, attribute, JS string, URL, CSS, JSON.
3. Use the smallest payload that proves script execution in your own browser.
4. Check whether authenticated context exposes meaningful actions/data.
5. Test CSP impact and whether payload requires user interaction.


### Tools that help without replacing manual work

Burp Repeater, browser DevTools, DOM Invader, reflection search.

### Evidence that usually proves impact

Script runs in victim origin and can perform authenticated actions or read sensitive data available to victim.

### Common false positives / informative-only cases

Self-XSS, alert on static brochureware, and payloads requiring console paste are usually low/informative.

### Report skeleton

```text
Title: Reflected XSS With Context-Aware Payloading allows [unauthorized action/data] in [asset/feature]
Asset: https://target.example/path
Prerequisites: Account A [role], Account B [role], both controlled by researcher
Steps:
1. Create controlled object/data as Account B.
2. Capture the vulnerable request as Account A.
3. Modify [exact field] from [A value] to [B value].
4. Send the request and observe [response/side effect].
5. Confirm in Account B UI that [unauthorized access/change] occurred.
Impact: [concrete business/security impact]
Suggested fix: Enforce server-side authorization for [object/function/property] on every request.
```

### Fast checklist

- [ ] Tested logged out, low role, high role, same tenant, different tenant where relevant.
- [ ] Changed one variable at a time.
- [ ] Used only controlled accounts/data.
- [ ] Captured before/after evidence.
- [ ] Explained why this is more than informative.


<div style="page-break-after: always;"></div>

## Page 25: Stored XSS in Shared or Privileged Views

**VRT alignment:** Client-Side Injection / Cross-Site Scripting  
**Best auth state:** Authenticated; user-to-user or user-to-admin path

### Why this is worth testing

Stored XSS becomes valuable when it reaches another user, admin, support agent, or tenant member.

### Manual test procedure

1. Place unique marker in profile fields, comments, filenames, support tickets, chat, address book, org names, webhook names, logs.
2. Find where marker is rendered to other accounts or admins.
3. Use harmless proof payload like `print()` in isolated field if permitted.
4. Check email templates and PDF/report rendering too.
5. Document victim path using your own second account or program-provided admin path.


### Tools that help without replacing manual work

Burp, browser profiles, Collaborator only if allowed for blind/admin XSS.

### Evidence that usually proves impact

Stored script executes for another user/admin and can perform actions or read data in that user’s context.

### Common false positives / informative-only cases

Do not leave payloads that can affect real users. Remove test content after reporting if safe.

### Report skeleton

```text
Title: Stored XSS in Shared or Privileged Views allows [unauthorized action/data] in [asset/feature]
Asset: https://target.example/path
Prerequisites: Account A [role], Account B [role], both controlled by researcher
Steps:
1. Create controlled object/data as Account B.
2. Capture the vulnerable request as Account A.
3. Modify [exact field] from [A value] to [B value].
4. Send the request and observe [response/side effect].
5. Confirm in Account B UI that [unauthorized access/change] occurred.
Impact: [concrete business/security impact]
Suggested fix: Enforce server-side authorization for [object/function/property] on every request.
```

### Fast checklist

- [ ] Tested logged out, low role, high role, same tenant, different tenant where relevant.
- [ ] Changed one variable at a time.
- [ ] Used only controlled accounts/data.
- [ ] Captured before/after evidence.
- [ ] Explained why this is more than informative.


<div style="page-break-after: always;"></div>

## Page 26: DOM XSS and Client-Side Route Injection

**VRT alignment:** Client-Side Injection  
**Best auth state:** Both public SPA and authenticated SPA

### Why this is worth testing

Modern SPAs process URL fragments, query strings, postMessage, localStorage, and JSON into the DOM.

### Manual test procedure

1. Search JavaScript for sinks: `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, dangerous template rendering.
2. Identify sources: `location`, `hash`, `search`, `postMessage`, storage, URLSearchParams.
3. Use marker and see if it reaches a sink.
4. Test route parameters, fragments, and encoded characters.
5. Check if exploit works from a clickable URL.


### Tools that help without replacing manual work

DevTools, DOM Invader, source maps, Burp browser.

### Evidence that usually proves impact

Attacker-controlled URL executes script in app origin, especially valuable in authenticated SPA with accessible APIs.

### Common false positives / informative-only cases

Do not report theoretical sink/source pairs without working execution path.

### Report skeleton

```text
Title: DOM XSS and Client-Side Route Injection allows [unauthorized action/data] in [asset/feature]
Asset: https://target.example/path
Prerequisites: Account A [role], Account B [role], both controlled by researcher
Steps:
1. Create controlled object/data as Account B.
2. Capture the vulnerable request as Account A.
3. Modify [exact field] from [A value] to [B value].
4. Send the request and observe [response/side effect].
5. Confirm in Account B UI that [unauthorized access/change] occurred.
Impact: [concrete business/security impact]
Suggested fix: Enforce server-side authorization for [object/function/property] on every request.
```

### Fast checklist

- [ ] Tested logged out, low role, high role, same tenant, different tenant where relevant.
- [ ] Changed one variable at a time.
- [ ] Used only controlled accounts/data.
- [ ] Captured before/after evidence.
- [ ] Explained why this is more than informative.


<div style="page-break-after: always;"></div>

## Page 27: Open Redirect With Real Security Impact

**VRT alignment:** Unvalidated Redirects and Forwards / Auth chain issue  
**Best auth state:** Often unauthenticated; valuable when chained

### Why this is worth testing

Open redirect alone is often low, but it can become high when used to steal OAuth codes, bypass allowlists, or leak tokens.

### Manual test procedure

1. Find redirect parameters: `next`, `url`, `return`, `continue`, `redirect_uri`, `callback`.
2. Test scheme-relative, encoded, double-encoded, backslash, path traversal, subdomain confusion.
3. Check if redirect endpoint is allowed in OAuth/SAML redirect allowlist.
4. Check if sensitive token appears in URL before redirect.
5. Test only to your own controlled domain.


### Tools that help without replacing manual work

Burp Repeater, browser, safe controlled domain/interactsh.

### Evidence that usually proves impact

OAuth/SAML code or token leak, account takeover chain, security allowlist bypass, trusted domain phishing risk only if program accepts it.

### Common false positives / informative-only cases

Do not report standalone redirect unless the program accepts it or you demonstrate a concrete chain.

### Report skeleton

```text
Title: Open Redirect With Real Security Impact allows [unauthorized action/data] in [asset/feature]
Asset: https://target.example/path
Prerequisites: Account A [role], Account B [role], both controlled by researcher
Steps:
1. Create controlled object/data as Account B.
2. Capture the vulnerable request as Account A.
3. Modify [exact field] from [A value] to [B value].
4. Send the request and observe [response/side effect].
5. Confirm in Account B UI that [unauthorized access/change] occurred.
Impact: [concrete business/security impact]
Suggested fix: Enforce server-side authorization for [object/function/property] on every request.
```

### Fast checklist

- [ ] Tested logged out, low role, high role, same tenant, different tenant where relevant.
- [ ] Changed one variable at a time.
- [ ] Used only controlled accounts/data.
- [ ] Captured before/after evidence.
- [ ] Explained why this is more than informative.


<div style="page-break-after: always;"></div>

## Page 28: Clickjacking on Sensitive Actions

**VRT alignment:** UI Redressing / Business Logic  
**Best auth state:** Authenticated victim simulation

### Why this is worth testing

Clickjacking matters when a framed page can cause meaningful state change or disclose sensitive UI through overlays.

### Manual test procedure

1. Check if sensitive page can be framed.
2. Build local iframe PoC against your own account.
3. Use actions like enable integration, change email, add API key, authorize OAuth, delete object only with disposable data.
4. Check if SameSite/CSRF still permits action.
5. Show realistic click path.


### Tools that help without replacing manual work

Local HTML PoC, browser profiles, Burp for request confirmation.

### Evidence that usually proves impact

Victim can be tricked into changing security settings, authorizing app, making payment-related change, or performing admin action.

### Common false positives / informative-only cases

Do not report clickjacking on static pages, logout, or harmless preference pages without impact.

### Report skeleton

```text
Title: Clickjacking on Sensitive Actions allows [unauthorized action/data] in [asset/feature]
Asset: https://target.example/path
Prerequisites: Account A [role], Account B [role], both controlled by researcher
Steps:
1. Create controlled object/data as Account B.
2. Capture the vulnerable request as Account A.
3. Modify [exact field] from [A value] to [B value].
4. Send the request and observe [response/side effect].
5. Confirm in Account B UI that [unauthorized access/change] occurred.
Impact: [concrete business/security impact]
Suggested fix: Enforce server-side authorization for [object/function/property] on every request.
```

### Fast checklist

- [ ] Tested logged out, low role, high role, same tenant, different tenant where relevant.
- [ ] Changed one variable at a time.
- [ ] Used only controlled accounts/data.
- [ ] Captured before/after evidence.
- [ ] Explained why this is more than informative.


<div style="page-break-after: always;"></div>

## Page 29: File Upload: Type, Extension, Content, and Serving Bugs

**VRT alignment:** File Upload / Server Security Misconfiguration / XSS  
**Best auth state:** Authenticated or unauthenticated upload endpoints

### Why this is worth testing

Uploads combine parsing, storage, content-type, filename, path, access control, virus scanning, thumbnailing, and rendering.

### Manual test procedure

1. Upload harmless text/image and capture request.
2. Change filename extension, MIME type, magic bytes, and multipart content type one at a time.
3. Check served `Content-Type` and `Content-Disposition`.
4. Try SVG/HTML only where allowed and verify if rendered as active content.
5. Test access control on uploaded file URL with Account B and logged out.


### Tools that help without replacing manual work

Burp multipart editor, exiftool, file command, browser, curl -I.

### Evidence that usually proves impact

Stored XSS via served SVG/HTML, private file accessible publicly, content sniffing, overwrite, path traversal in filename, malware-like content accepted where policy says blocked.

### Common false positives / informative-only cases

Do not upload web shells or malware to production. Use harmless files and stop at validation bypass unless explicit RCE testing is permitted.

### Report skeleton

```text
Title: File Upload: Type, Extension, Content, and Serving Bugs allows [unauthorized action/data] in [asset/feature]
Asset: https://target.example/path
Prerequisites: Account A [role], Account B [role], both controlled by researcher
Steps:
1. Create controlled object/data as Account B.
2. Capture the vulnerable request as Account A.
3. Modify [exact field] from [A value] to [B value].
4. Send the request and observe [response/side effect].
5. Confirm in Account B UI that [unauthorized access/change] occurred.
Impact: [concrete business/security impact]
Suggested fix: Enforce server-side authorization for [object/function/property] on every request.
```

### Fast checklist

- [ ] Tested logged out, low role, high role, same tenant, different tenant where relevant.
- [ ] Changed one variable at a time.
- [ ] Used only controlled accounts/data.
- [ ] Captured before/after evidence.
- [ ] Explained why this is more than informative.


<div style="page-break-after: always;"></div>

## Page 30: File Upload to Code Execution: Safe Boundary

**VRT alignment:** Remote Code Execution / File Upload  
**Best auth state:** Authenticated upload features; only where program permits

### Why this is worth testing

Executable upload is serious, but testing must avoid harmful web shells and persistence.

### Manual test procedure

1. First prove storage and serving path with harmless file.
2. Check whether server executes uploaded dynamic extensions only in a lab or explicit-permission target.
3. Prefer non-destructive proof such as rendering a static marker, not executing commands.
4. If execution proof is permitted, use minimal benign output and no system access.
5. Immediately remove uploaded test file if possible.


### Tools that help without replacing manual work

Burp, curl, browser, disposable test file.

### Evidence that usually proves impact

Server executes attacker-supplied code from uploaded content, potentially full server compromise.

### Common false positives / informative-only cases

No reverse shells, no persistence, no credential access, no filesystem browsing, no destructive commands.

### Report skeleton

```text
Title: File Upload to Code Execution: Safe Boundary allows [unauthorized action/data] in [asset/feature]
Asset: https://target.example/path
Prerequisites: Account A [role], Account B [role], both controlled by researcher
Steps:
1. Create controlled object/data as Account B.
2. Capture the vulnerable request as Account A.
3. Modify [exact field] from [A value] to [B value].
4. Send the request and observe [response/side effect].
5. Confirm in Account B UI that [unauthorized access/change] occurred.
Impact: [concrete business/security impact]
Suggested fix: Enforce server-side authorization for [object/function/property] on every request.
```

### Fast checklist

- [ ] Tested logged out, low role, high role, same tenant, different tenant where relevant.
- [ ] Changed one variable at a time.
- [ ] Used only controlled accounts/data.
- [ ] Captured before/after evidence.
- [ ] Explained why this is more than informative.


<div style="page-break-after: always;"></div>

## Page 31: Path Traversal and Arbitrary File Read

**VRT alignment:** Server-Side Injection / Path Traversal / Sensitive Data Exposure  
**Best auth state:** Both; common in download, template, image, import endpoints

### Why this is worth testing

File read bugs are often found in parameters that reference filenames, report templates, themes, language packs, or attachments.

### Manual test procedure

1. Identify parameters like `file`, `path`, `template`, `download`, `image`, `locale`.
2. Use harmless traversal to request known non-sensitive app file where possible.
3. Try encoded variants and path normalization differences.
4. Test Windows and Linux separators.
5. Stop if sensitive file access is shown; do not dump files.


### Tools that help without replacing manual work

Burp Repeater, URL encoder, curl.

### Evidence that usually proves impact

Read private uploads, config files, source, environment variables, logs, or credentials.

### Common false positives / informative-only cases

Do not exfiltrate `/etc/passwd`, cloud keys, or secrets beyond minimal proof permitted by policy. A readable public asset is not enough.

### Report skeleton

```text
Title: Path Traversal and Arbitrary File Read allows [unauthorized action/data] in [asset/feature]
Asset: https://target.example/path
Prerequisites: Account A [role], Account B [role], both controlled by researcher
Steps:
1. Create controlled object/data as Account B.
2. Capture the vulnerable request as Account A.
3. Modify [exact field] from [A value] to [B value].
4. Send the request and observe [response/side effect].
5. Confirm in Account B UI that [unauthorized access/change] occurred.
Impact: [concrete business/security impact]
Suggested fix: Enforce server-side authorization for [object/function/property] on every request.
```

### Fast checklist

- [ ] Tested logged out, low role, high role, same tenant, different tenant where relevant.
- [ ] Changed one variable at a time.
- [ ] Used only controlled accounts/data.
- [ ] Captured before/after evidence.
- [ ] Explained why this is more than informative.


<div style="page-break-after: always;"></div>

## Page 32: SSRF: URL Fetchers, Webhooks, Importers, and Metadata Risk

**VRT alignment:** Server-Side Request Forgery / Server Security Misconfiguration  
**Best auth state:** Both; often authenticated integrations

### Why this is worth testing

Any server-side URL fetcher can become SSRF: webhooks, image import, PDF generation, URL preview, avatar import, SSO metadata, OpenAPI import.

### Manual test procedure

1. Find URL-taking inputs.
2. Submit your collaborator/interactsh URL and look for callback.
3. Check whether response is reflected or only blind.
4. Test redirect following using your own redirect endpoint.
5. Do not scan internal networks or cloud metadata unless explicitly allowed.


### Tools that help without replacing manual work

Burp Collaborator, interactsh, local redirect endpoint, Repeater.

### Evidence that usually proves impact

Server can be induced to make requests to attacker-controlled or internal destinations; may expose internal data, credentials, or admin services depending on permissions.

### Common false positives / informative-only cases

No internal port scanning, no metadata credential extraction, no high-volume callbacks.

### Report skeleton

```text
Title: SSRF: URL Fetchers, Webhooks, Importers, and Metadata Risk allows [unauthorized action/data] in [asset/feature]
Asset: https://target.example/path
Prerequisites: Account A [role], Account B [role], both controlled by researcher
Steps:
1. Create controlled object/data as Account B.
2. Capture the vulnerable request as Account A.
3. Modify [exact field] from [A value] to [B value].
4. Send the request and observe [response/side effect].
5. Confirm in Account B UI that [unauthorized access/change] occurred.
Impact: [concrete business/security impact]
Suggested fix: Enforce server-side authorization for [object/function/property] on every request.
```

### Fast checklist

- [ ] Tested logged out, low role, high role, same tenant, different tenant where relevant.
- [ ] Changed one variable at a time.
- [ ] Used only controlled accounts/data.
- [ ] Captured before/after evidence.
- [ ] Explained why this is more than informative.


<div style="page-break-after: always;"></div>

## Page 33: XXE in XML, SVG, Office, SAML, SOAP, and Importers

**VRT alignment:** XML External Entity Injection / SSRF / File Read  
**Best auth state:** Usually authenticated upload/import/API

### Why this is worth testing

XML parsers may resolve external entities in file import, SAML, SOAP, SVG, DOCX/XLSX, and legacy APIs.

### Manual test procedure

1. Identify XML-consuming endpoints.
2. Use harmless external entity callback to your controlled domain where allowed.
3. Try SVG or Office document import if parser is server-side.
4. Check for parser errors indicating entity resolution.
5. Stop at callback proof unless file read is explicitly allowed.


### Tools that help without replacing manual work

Burp, Collaborator/interactsh, simple XML files, zip tools for Office documents.

### Evidence that usually proves impact

Server-side file read, SSRF, or sensitive data disclosure through XML parser behavior.

### Common false positives / informative-only cases

Do not read sensitive files or use billion-laughs/entity expansion DoS payloads.

### Report skeleton

```text
Title: XXE in XML, SVG, Office, SAML, SOAP, and Importers allows [unauthorized action/data] in [asset/feature]
Asset: https://target.example/path
Prerequisites: Account A [role], Account B [role], both controlled by researcher
Steps:
1. Create controlled object/data as Account B.
2. Capture the vulnerable request as Account A.
3. Modify [exact field] from [A value] to [B value].
4. Send the request and observe [response/side effect].
5. Confirm in Account B UI that [unauthorized access/change] occurred.
Impact: [concrete business/security impact]
Suggested fix: Enforce server-side authorization for [object/function/property] on every request.
```

### Fast checklist

- [ ] Tested logged out, low role, high role, same tenant, different tenant where relevant.
- [ ] Changed one variable at a time.
- [ ] Used only controlled accounts/data.
- [ ] Captured before/after evidence.
- [ ] Explained why this is more than informative.


<div style="page-break-after: always;"></div>

## Page 34: SQL Injection: Safe Manual Detection

**VRT alignment:** Server-Side Injection / SQL Injection  
**Best auth state:** Both; any user-controlled input reaching SQL

### Why this is worth testing

SQLi remains high impact, but safe testing matters. Manual detection focuses on response differences and errors, not dumping data.

### Manual test procedure

1. Test parameters with single quote and syntax markers; look for controlled errors.
2. Use boolean true/false differentials only on read-only endpoints.
3. Use time-based checks sparingly and only where allowed.
4. Test JSON, XML, headers, cookies, sort/order parameters, search filters.
5. Stop when vulnerability is proven; do not enumerate tables or extract data.


### Tools that help without replacing manual work

Burp Repeater/Comparer, logger, sqlmap only if explicitly allowed and rate-limited.

### Evidence that usually proves impact

Unauthorized data access/modification, auth bypass, sensitive data exposure, sometimes server compromise.

### Common false positives / informative-only cases

Avoid `OR 1=1` on state-changing endpoints. Do not dump databases. Do not run sqlmap aggressively.

### Report skeleton

```text
Title: SQL Injection: Safe Manual Detection allows [unauthorized action/data] in [asset/feature]
Asset: https://target.example/path
Prerequisites: Account A [role], Account B [role], both controlled by researcher
Steps:
1. Create controlled object/data as Account B.
2. Capture the vulnerable request as Account A.
3. Modify [exact field] from [A value] to [B value].
4. Send the request and observe [response/side effect].
5. Confirm in Account B UI that [unauthorized access/change] occurred.
Impact: [concrete business/security impact]
Suggested fix: Enforce server-side authorization for [object/function/property] on every request.
```

### Fast checklist

- [ ] Tested logged out, low role, high role, same tenant, different tenant where relevant.
- [ ] Changed one variable at a time.
- [ ] Used only controlled accounts/data.
- [ ] Captured before/after evidence.
- [ ] Explained why this is more than informative.


<div style="page-break-after: always;"></div>

## Page 35: NoSQL Injection in JSON APIs and Login/Search Filters

**VRT alignment:** Server-Side Injection / Authentication Bypass / Data Exposure  
**Best auth state:** Both; login, search, filters, Mongo-like APIs

### Why this is worth testing

JSON APIs may pass objects directly to NoSQL query builders. Type confusion can bypass filters or auth.

### Manual test procedure

1. Identify JSON fields used in login/search/filter.
2. Change scalar string to object/array where safe.
3. Compare normal false condition vs altered operator-like input.
4. Test only against your own accounts and read-only endpoints.
5. Look for broad result sets or auth bypass with controlled account.


### Tools that help without replacing manual work

Burp Repeater, JSON editor, Comparer.

### Evidence that usually proves impact

Authentication bypass, reading other records, bypassing filters, exposing private data.

### Common false positives / informative-only cases

Do not brute force or dump collections. Do not send destructive operators.

### Report skeleton

```text
Title: NoSQL Injection in JSON APIs and Login/Search Filters allows [unauthorized action/data] in [asset/feature]
Asset: https://target.example/path
Prerequisites: Account A [role], Account B [role], both controlled by researcher
Steps:
1. Create controlled object/data as Account B.
2. Capture the vulnerable request as Account A.
3. Modify [exact field] from [A value] to [B value].
4. Send the request and observe [response/side effect].
5. Confirm in Account B UI that [unauthorized access/change] occurred.
Impact: [concrete business/security impact]
Suggested fix: Enforce server-side authorization for [object/function/property] on every request.
```

### Fast checklist

- [ ] Tested logged out, low role, high role, same tenant, different tenant where relevant.
- [ ] Changed one variable at a time.
- [ ] Used only controlled accounts/data.
- [ ] Captured before/after evidence.
- [ ] Explained why this is more than informative.


<div style="page-break-after: always;"></div>

## Page 36: Server-Side Template Injection: Math Probe to Impact

**VRT alignment:** Server-Side Injection / Template Injection  
**Best auth state:** Both; often authenticated templates, emails, PDFs, names

### Why this is worth testing

User-controlled data rendered through server templates can lead from expression evaluation to code execution.

### Manual test procedure

1. Find fields rendered in emails, PDFs, invoices, reports, themes, notifications.
2. Use harmless math probes like template-specific `7*7` equivalents.
3. Check delayed rendering locations, not only immediate response.
4. Identify engine from syntax/error differences.
5. Stop at expression evaluation unless RCE testing is explicitly allowed.


### Tools that help without replacing manual work

Burp, test email inbox, PDF/report download, template error notes.

### Evidence that usually proves impact

Template expression execution, data exposure, potentially RCE depending on engine and sandbox.

### Common false positives / informative-only cases

No command execution payloads on production unless explicitly authorized.

### Report skeleton

```text
Title: Server-Side Template Injection: Math Probe to Impact allows [unauthorized action/data] in [asset/feature]
Asset: https://target.example/path
Prerequisites: Account A [role], Account B [role], both controlled by researcher
Steps:
1. Create controlled object/data as Account B.
2. Capture the vulnerable request as Account A.
3. Modify [exact field] from [A value] to [B value].
4. Send the request and observe [response/side effect].
5. Confirm in Account B UI that [unauthorized access/change] occurred.
Impact: [concrete business/security impact]
Suggested fix: Enforce server-side authorization for [object/function/property] on every request.
```

### Fast checklist

- [ ] Tested logged out, low role, high role, same tenant, different tenant where relevant.
- [ ] Changed one variable at a time.
- [ ] Used only controlled accounts/data.
- [ ] Captured before/after evidence.
- [ ] Explained why this is more than informative.


<div style="page-break-after: always;"></div>

## Page 37: Command Injection: Minimal Non-Destructive Proof

**VRT alignment:** Server-Side Injection / OS Command Injection  
**Best auth state:** Both; network tools, converters, importers, ping/traceroute, image/video processing

### Why this is worth testing

Command injection is severe, but must be proven with minimal harmless signals.

### Manual test procedure

1. Identify parameters likely passed to shell commands.
2. Use syntax-break probes and benign time delay where allowed.
3. Prefer out-of-band callback to your domain over output extraction.
4. Check filename metadata and archive processing paths.
5. Stop after proving execution; no filesystem or credential access.


### Tools that help without replacing manual work

Burp Repeater, Collaborator/interactsh, controlled file metadata.

### Evidence that usually proves impact

Server executes attacker-controlled shell metacharacters, potentially full host compromise.

### Common false positives / informative-only cases

No reverse shells, no `cat` secrets, no destructive commands, no persistence.

### Report skeleton

```text
Title: Command Injection: Minimal Non-Destructive Proof allows [unauthorized action/data] in [asset/feature]
Asset: https://target.example/path
Prerequisites: Account A [role], Account B [role], both controlled by researcher
Steps:
1. Create controlled object/data as Account B.
2. Capture the vulnerable request as Account A.
3. Modify [exact field] from [A value] to [B value].
4. Send the request and observe [response/side effect].
5. Confirm in Account B UI that [unauthorized access/change] occurred.
Impact: [concrete business/security impact]
Suggested fix: Enforce server-side authorization for [object/function/property] on every request.
```

### Fast checklist

- [ ] Tested logged out, low role, high role, same tenant, different tenant where relevant.
- [ ] Changed one variable at a time.
- [ ] Used only controlled accounts/data.
- [ ] Captured before/after evidence.
- [ ] Explained why this is more than informative.


<div style="page-break-after: always;"></div>

## Page 38: HTTP Request Smuggling and Desync: Manual Triage

**VRT alignment:** Server Security Misconfiguration / Request Smuggling  
**Best auth state:** Both; edge/proxy/backend mismatch

### Why this is worth testing

Request smuggling can poison queues, bypass access controls, or hijack requests, but careless testing can affect other users.

### Manual test procedure

1. Only test if program permits desync testing.
2. Use Burp HTTP Request Smuggler in safe modes or manual CL/TE differential probes.
3. Target low-risk endpoints and avoid affecting live users.
4. Look for self-contained response queue poisoning against your own follow-up request.
5. Stop if evidence suggests cross-user impact.


### Tools that help without replacing manual work

Burp Repeater, HTTP Request Smuggler extension, isolated test endpoint.

### Evidence that usually proves impact

Request routing confusion, auth bypass, cache poisoning, response queue poisoning, cross-user request capture.

### Common false positives / informative-only cases

Do not run broad automated desync scans without permission. Avoid production endpoints with high user traffic.

### Report skeleton

```text
Title: HTTP Request Smuggling and Desync: Manual Triage allows [unauthorized action/data] in [asset/feature]
Asset: https://target.example/path
Prerequisites: Account A [role], Account B [role], both controlled by researcher
Steps:
1. Create controlled object/data as Account B.
2. Capture the vulnerable request as Account A.
3. Modify [exact field] from [A value] to [B value].
4. Send the request and observe [response/side effect].
5. Confirm in Account B UI that [unauthorized access/change] occurred.
Impact: [concrete business/security impact]
Suggested fix: Enforce server-side authorization for [object/function/property] on every request.
```

### Fast checklist

- [ ] Tested logged out, low role, high role, same tenant, different tenant where relevant.
- [ ] Changed one variable at a time.
- [ ] Used only controlled accounts/data.
- [ ] Captured before/after evidence.
- [ ] Explained why this is more than informative.


<div style="page-break-after: always;"></div>

## Page 39: Web Cache Poisoning

**VRT alignment:** Server Security Misconfiguration / Cache Poisoning / XSS chain  
**Best auth state:** Usually unauthenticated public pages; sometimes authenticated shared caches

### Why this is worth testing

If unkeyed headers or parameters influence cached responses, one user can poison content served to others.

### Manual test procedure

1. Identify cached responses via `Age`, `X-Cache`, `CF-Cache-Status`.
2. Add cache-buster parameter you control.
3. Change benign headers/params and see if response changes.
4. Check whether changed response is cached and served to second request.
5. Use harmless marker only; do not poison popular pages.


### Tools that help without replacing manual work

Burp Repeater, Param Miner, curl, cache-buster notes.

### Evidence that usually proves impact

Stored defacement, stored XSS, redirect poisoning, sensitive data leakage, denial of service on cached endpoint.

### Common false positives / informative-only cases

Do not poison live high-traffic pages. Do not use offensive payloads; use markers.

### Report skeleton

```text
Title: Web Cache Poisoning allows [unauthorized action/data] in [asset/feature]
Asset: https://target.example/path
Prerequisites: Account A [role], Account B [role], both controlled by researcher
Steps:
1. Create controlled object/data as Account B.
2. Capture the vulnerable request as Account A.
3. Modify [exact field] from [A value] to [B value].
4. Send the request and observe [response/side effect].
5. Confirm in Account B UI that [unauthorized access/change] occurred.
Impact: [concrete business/security impact]
Suggested fix: Enforce server-side authorization for [object/function/property] on every request.
```

### Fast checklist

- [ ] Tested logged out, low role, high role, same tenant, different tenant where relevant.
- [ ] Changed one variable at a time.
- [ ] Used only controlled accounts/data.
- [ ] Captured before/after evidence.
- [ ] Explained why this is more than informative.


<div style="page-break-after: always;"></div>

## Page 40: Web Cache Deception

**VRT alignment:** Sensitive Data Exposure / Cache Misconfiguration  
**Best auth state:** Authenticated victim simulation

### Why this is worth testing

Private responses may be cached if URL path tricks make dynamic pages look static.

### Manual test procedure

1. Find authenticated pages with sensitive data.
2. Append path segments like `/profile.css` or encoded delimiters where app routing permits.
3. Check cache headers and second unauthenticated request.
4. Use your own account data only.
5. Confirm sensitive body is served from cache to logged-out browser.


### Tools that help without replacing manual work

Burp Repeater, browser profiles, curl -I.

### Evidence that usually proves impact

Private authenticated data can be cached and retrieved by unauthenticated users.

### Common false positives / informative-only cases

Do not test with real user data. A cache hit on public data is not a bug.

### Report skeleton

```text
Title: Web Cache Deception allows [unauthorized action/data] in [asset/feature]
Asset: https://target.example/path
Prerequisites: Account A [role], Account B [role], both controlled by researcher
Steps:
1. Create controlled object/data as Account B.
2. Capture the vulnerable request as Account A.
3. Modify [exact field] from [A value] to [B value].
4. Send the request and observe [response/side effect].
5. Confirm in Account B UI that [unauthorized access/change] occurred.
Impact: [concrete business/security impact]
Suggested fix: Enforce server-side authorization for [object/function/property] on every request.
```

### Fast checklist

- [ ] Tested logged out, low role, high role, same tenant, different tenant where relevant.
- [ ] Changed one variable at a time.
- [ ] Used only controlled accounts/data.
- [ ] Captured before/after evidence.
- [ ] Explained why this is more than informative.


<div style="page-break-after: always;"></div>

## Page 41: GraphQL: Introspection, BOLA, BFLA, and Over-Posting

**VRT alignment:** API Security / Broken Access Control / Information Disclosure  
**Best auth state:** Both; authenticated APIs are most fruitful

### Why this is worth testing

GraphQL exposes object and function boundaries through schemas, variables, and resolvers. Authorization bugs often hide at resolver level.

### Manual test procedure

1. Check if introspection is enabled; treat as recon unless sensitive schema/hidden admin ops are exploitable.
2. Create A/B objects and swap IDs in variables.
3. Try admin mutations as normal user.
4. Check nested fields for unauthorized data exposure.
5. Try adding fields to mutations that UI does not use.


### Tools that help without replacing manual work

GraphQL Voyager, Altair, InQL, Burp Repeater, jq.

### Evidence that usually proves impact

BOLA/BFLA, hidden admin operations callable, sensitive nested fields exposed, tenant data leakage, mass assignment-like mutation issues.

### Common false positives / informative-only cases

Do not report introspection alone unless policy accepts it or it exposes sensitive non-public operations with exploit path.

### Report skeleton

```text
Title: GraphQL: Introspection, BOLA, BFLA, and Over-Posting allows [unauthorized action/data] in [asset/feature]
Asset: https://target.example/path
Prerequisites: Account A [role], Account B [role], both controlled by researcher
Steps:
1. Create controlled object/data as Account B.
2. Capture the vulnerable request as Account A.
3. Modify [exact field] from [A value] to [B value].
4. Send the request and observe [response/side effect].
5. Confirm in Account B UI that [unauthorized access/change] occurred.
Impact: [concrete business/security impact]
Suggested fix: Enforce server-side authorization for [object/function/property] on every request.
```

### Fast checklist

- [ ] Tested logged out, low role, high role, same tenant, different tenant where relevant.
- [ ] Changed one variable at a time.
- [ ] Used only controlled accounts/data.
- [ ] Captured before/after evidence.
- [ ] Explained why this is more than informative.


<div style="page-break-after: always;"></div>

## Page 42: WebSocket Authorization and Message Tampering

**VRT alignment:** Broken Access Control / Real-Time API Security  
**Best auth state:** Authenticated real-time features

### Why this is worth testing

WebSocket messages often implement custom routing and auth that differs from REST APIs.

### Manual test procedure

1. Capture connection and messages.
2. Replay messages with Account B session.
3. Change roomId, tenantId, userId, role, event type.
4. Test subscribe/listen operations separately from send operations.
5. Verify whether unauthorized messages or data streams appear.


### Tools that help without replacing manual work

Burp WebSockets history, DevTools WS frames, browser profiles.

### Evidence that usually proves impact

Read another chat/notification stream, send messages as another user, subscribe to tenant events, perform admin real-time actions.

### Common false positives / informative-only cases

Do not spam real-time channels or message real users.

### Report skeleton

```text
Title: WebSocket Authorization and Message Tampering allows [unauthorized action/data] in [asset/feature]
Asset: https://target.example/path
Prerequisites: Account A [role], Account B [role], both controlled by researcher
Steps:
1. Create controlled object/data as Account B.
2. Capture the vulnerable request as Account A.
3. Modify [exact field] from [A value] to [B value].
4. Send the request and observe [response/side effect].
5. Confirm in Account B UI that [unauthorized access/change] occurred.
Impact: [concrete business/security impact]
Suggested fix: Enforce server-side authorization for [object/function/property] on every request.
```

### Fast checklist

- [ ] Tested logged out, low role, high role, same tenant, different tenant where relevant.
- [ ] Changed one variable at a time.
- [ ] Used only controlled accounts/data.
- [ ] Captured before/after evidence.
- [ ] Explained why this is more than informative.


<div style="page-break-after: always;"></div>

## Page 43: Business Logic: Workflow Step Skipping

**VRT alignment:** Business Logic / Access Control  
**Best auth state:** Both; usually authenticated

### Why this is worth testing

Business workflows expect steps in order. Servers often validate each endpoint but not the full state machine.

### Manual test procedure

1. Map required steps: cart→payment→confirmation, draft→approval→publish, signup→verify→activate.
2. Capture final-step request.
3. Replay final step before completing earlier steps.
4. Change status fields in requests.
5. Try duplicate finalization after cancellation/refund/removal.


### Tools that help without replacing manual work

Burp Repeater, browser profiles, workflow diagram.

### Evidence that usually proves impact

Bypass payment/approval/verification, publish without review, access feature before subscription, complete action after cancellation.

### Common false positives / informative-only cases

Do not perform real financial harm. Use sandbox/test objects and stop before irreversible actions.

### Report skeleton

```text
Title: Business Logic: Workflow Step Skipping allows [unauthorized action/data] in [asset/feature]
Asset: https://target.example/path
Prerequisites: Account A [role], Account B [role], both controlled by researcher
Steps:
1. Create controlled object/data as Account B.
2. Capture the vulnerable request as Account A.
3. Modify [exact field] from [A value] to [B value].
4. Send the request and observe [response/side effect].
5. Confirm in Account B UI that [unauthorized access/change] occurred.
Impact: [concrete business/security impact]
Suggested fix: Enforce server-side authorization for [object/function/property] on every request.
```

### Fast checklist

- [ ] Tested logged out, low role, high role, same tenant, different tenant where relevant.
- [ ] Changed one variable at a time.
- [ ] Used only controlled accounts/data.
- [ ] Captured before/after evidence.
- [ ] Explained why this is more than informative.


<div style="page-break-after: always;"></div>

## Page 44: Business Logic: Price, Quantity, Coupon, and Subscription Tampering

**VRT alignment:** Business Logic / Payment Logic  
**Best auth state:** Authenticated; sometimes checkout guest

### Why this is worth testing

Checkout and billing flows are manually testable and often have real business impact.

### Manual test procedure

1. Capture cart/checkout/subscription requests.
2. Change price, quantity, currency, discount, plan, interval, tax, shipping, trial days.
3. Try negative/zero/decimal/large quantities only on test/sandbox checkout.
4. Check server-side recalculation by final invoice/order.
5. Test coupon reuse, stacking, tenant transfer, and referral self-use.


### Tools that help without replacing manual work

Burp Repeater, test payment mode only, browser checkout.

### Evidence that usually proves impact

Underpayment, free subscription, unauthorized upgrade, coupon abuse, referral abuse, tax/shipping bypass.

### Common false positives / informative-only cases

Do not complete real purchases without permission. Do not cause financial loss; use test mode or stop at pre-payment proof.

### Report skeleton

```text
Title: Business Logic: Price, Quantity, Coupon, and Subscription Tampering allows [unauthorized action/data] in [asset/feature]
Asset: https://target.example/path
Prerequisites: Account A [role], Account B [role], both controlled by researcher
Steps:
1. Create controlled object/data as Account B.
2. Capture the vulnerable request as Account A.
3. Modify [exact field] from [A value] to [B value].
4. Send the request and observe [response/side effect].
5. Confirm in Account B UI that [unauthorized access/change] occurred.
Impact: [concrete business/security impact]
Suggested fix: Enforce server-side authorization for [object/function/property] on every request.
```

### Fast checklist

- [ ] Tested logged out, low role, high role, same tenant, different tenant where relevant.
- [ ] Changed one variable at a time.
- [ ] Used only controlled accounts/data.
- [ ] Captured before/after evidence.
- [ ] Explained why this is more than informative.


<div style="page-break-after: always;"></div>

## Page 45: Race Conditions and Double-Spend Logic

**VRT alignment:** Business Logic / Race Condition  
**Best auth state:** Authenticated; high-value state changes

### Why this is worth testing

Concurrent requests can bypass single-use assumptions for coupons, invites, password resets, transfers, and inventory.

### Manual test procedure

1. Identify single-use action.
2. Prepare two identical requests with same token/coupon/resource.
3. Send in a small synchronized burst against your own account only.
4. Check if both succeed.
5. Keep volume tiny and repeat only enough to prove.


### Tools that help without replacing manual work

Burp Repeater tab groups, Turbo Intruder only if allowed and very low volume.

### Evidence that usually proves impact

Coupon redeemed twice, balance spent twice, invite accepted twice, reset token used twice, inventory oversold, MFA code reused.

### Common false positives / informative-only cases

No high-volume race testing. Do not target money movement or live inventory without explicit permission.

### Report skeleton

```text
Title: Race Conditions and Double-Spend Logic allows [unauthorized action/data] in [asset/feature]
Asset: https://target.example/path
Prerequisites: Account A [role], Account B [role], both controlled by researcher
Steps:
1. Create controlled object/data as Account B.
2. Capture the vulnerable request as Account A.
3. Modify [exact field] from [A value] to [B value].
4. Send the request and observe [response/side effect].
5. Confirm in Account B UI that [unauthorized access/change] occurred.
Impact: [concrete business/security impact]
Suggested fix: Enforce server-side authorization for [object/function/property] on every request.
```

### Fast checklist

- [ ] Tested logged out, low role, high role, same tenant, different tenant where relevant.
- [ ] Changed one variable at a time.
- [ ] Used only controlled accounts/data.
- [ ] Captured before/after evidence.
- [ ] Explained why this is more than informative.


<div style="page-break-after: always;"></div>

## Page 46: Rate Limits on Security-Sensitive and Costly Flows

**VRT alignment:** Authentication / API Unrestricted Resource Consumption / Abuse  
**Best auth state:** Both; depends endpoint

### Why this is worth testing

Rate limiting is reportable when abuse affects account security, cost, availability, or business integrity.

### Manual test procedure

1. Test tiny controlled counts only.
2. Prioritize password reset, OTP, MFA, invite email, export generation, expensive search, SMS, PDF rendering.
3. Check per-IP vs per-account vs per-token controls.
4. Check distributed bypass only conceptually unless allowed.
5. Document cost/security impact.


### Tools that help without replacing manual work

Burp Intruder with low request count, curl loop with sleep, manual counters.

### Evidence that usually proves impact

OTP brute force risk, inbox/SMS flooding, account lockout abuse, cost amplification, resource exhaustion, sensitive business flow abuse.

### Common false positives / informative-only cases

Do not DoS. Missing rate limit on low-risk normal browsing is often not enough.

### Report skeleton

```text
Title: Rate Limits on Security-Sensitive and Costly Flows allows [unauthorized action/data] in [asset/feature]
Asset: https://target.example/path
Prerequisites: Account A [role], Account B [role], both controlled by researcher
Steps:
1. Create controlled object/data as Account B.
2. Capture the vulnerable request as Account A.
3. Modify [exact field] from [A value] to [B value].
4. Send the request and observe [response/side effect].
5. Confirm in Account B UI that [unauthorized access/change] occurred.
Impact: [concrete business/security impact]
Suggested fix: Enforce server-side authorization for [object/function/property] on every request.
```

### Fast checklist

- [ ] Tested logged out, low role, high role, same tenant, different tenant where relevant.
- [ ] Changed one variable at a time.
- [ ] Used only controlled accounts/data.
- [ ] Captured before/after evidence.
- [ ] Explained why this is more than informative.


<div style="page-break-after: always;"></div>

## Page 47: Sensitive Data Exposure in Responses, Exports, Logs, and Source Maps

**VRT alignment:** Sensitive Data Exposure  
**Best auth state:** Both; often authenticated API responses

### Why this is worth testing

APIs often return more data than UI displays; source maps and logs may reveal secrets or hidden endpoints.

### Manual test procedure

1. Inspect raw API responses for hidden fields: tokens, emails, phone, roles, internal IDs, billing details.
2. Check export/report endpoints for overbroad data.
3. Look for source maps in production JS.
4. Search source maps for secrets and hidden routes.
5. Check logs/debug endpoints only in scope.


### Tools that help without replacing manual work

DevTools, Burp, jq, ripgrep on downloaded JS/maps.

### Evidence that usually proves impact

Private PII, secrets, auth tokens, API keys, internal endpoints, tenant data, or credentials exposed.

### Common false positives / informative-only cases

Do not report internal IDs alone unless they enable another attack. Do not download large datasets.

### Report skeleton

```text
Title: Sensitive Data Exposure in Responses, Exports, Logs, and Source Maps allows [unauthorized action/data] in [asset/feature]
Asset: https://target.example/path
Prerequisites: Account A [role], Account B [role], both controlled by researcher
Steps:
1. Create controlled object/data as Account B.
2. Capture the vulnerable request as Account A.
3. Modify [exact field] from [A value] to [B value].
4. Send the request and observe [response/side effect].
5. Confirm in Account B UI that [unauthorized access/change] occurred.
Impact: [concrete business/security impact]
Suggested fix: Enforce server-side authorization for [object/function/property] on every request.
```

### Fast checklist

- [ ] Tested logged out, low role, high role, same tenant, different tenant where relevant.
- [ ] Changed one variable at a time.
- [ ] Used only controlled accounts/data.
- [ ] Captured before/after evidence.
- [ ] Explained why this is more than informative.


<div style="page-break-after: always;"></div>

## Page 48: Cloud Storage and Public Bucket Exposure

**VRT alignment:** Sensitive Data Exposure / Security Misconfiguration  
**Best auth state:** Often unauthenticated direct object URLs

### Why this is worth testing

S3/GCS/Azure blobs often store uploads, backups, exports, and logs. Access control mistakes can expose sensitive data.

### Manual test procedure

1. Identify storage URLs from app traffic.
2. Test direct access to your own uploaded file logged out.
3. Check listing only if bucket endpoint reveals it naturally and rules permit.
4. Look for backups/logs only in scoped assets.
5. Do not enumerate unrelated buckets.


### Tools that help without replacing manual work

curl, browser, cloud URL parser, Burp.

### Evidence that usually proves impact

Private uploads, exports, backups, logs, invoices, or secrets publicly readable; public write enabling stored XSS or content abuse.

### Common false positives / informative-only cases

Do not mass enumerate bucket names. Public marketing assets are not a bug.

### Report skeleton

```text
Title: Cloud Storage and Public Bucket Exposure allows [unauthorized action/data] in [asset/feature]
Asset: https://target.example/path
Prerequisites: Account A [role], Account B [role], both controlled by researcher
Steps:
1. Create controlled object/data as Account B.
2. Capture the vulnerable request as Account A.
3. Modify [exact field] from [A value] to [B value].
4. Send the request and observe [response/side effect].
5. Confirm in Account B UI that [unauthorized access/change] occurred.
Impact: [concrete business/security impact]
Suggested fix: Enforce server-side authorization for [object/function/property] on every request.
```

### Fast checklist

- [ ] Tested logged out, low role, high role, same tenant, different tenant where relevant.
- [ ] Changed one variable at a time.
- [ ] Used only controlled accounts/data.
- [ ] Captured before/after evidence.
- [ ] Explained why this is more than informative.


<div style="page-break-after: always;"></div>

## Page 49: Subdomain Takeover and Dangling External References

**VRT alignment:** Server Security Misconfiguration / Subdomain Takeover  
**Best auth state:** Unauthenticated recon

### Why this is worth testing

Dangling DNS records to SaaS providers may allow takeover, but false positives are common and program rules vary.

### Manual test procedure

1. Find CNAMEs pointing to deprovisioned services.
2. Verify provider-specific takeover fingerprint from reliable source.
3. Claim only a harmless proof page if rules allow.
4. Check impact: cookies, OAuth redirect allowlists, brand trust, same-site assumptions.
5. Document DNS evidence and provider response.


### Tools that help without replacing manual work

dig, httpx, nuclei takeover templates for verification only, browser.

### Evidence that usually proves impact

Attacker controls subdomain under target domain, enabling phishing, cookie scope abuse, OAuth redirect abuse, or content hosting.

### Common false positives / informative-only cases

Do not take over assets if program forbids it. Avoid false positives where provider blocks arbitrary claims.

### Report skeleton

```text
Title: Subdomain Takeover and Dangling External References allows [unauthorized action/data] in [asset/feature]
Asset: https://target.example/path
Prerequisites: Account A [role], Account B [role], both controlled by researcher
Steps:
1. Create controlled object/data as Account B.
2. Capture the vulnerable request as Account A.
3. Modify [exact field] from [A value] to [B value].
4. Send the request and observe [response/side effect].
5. Confirm in Account B UI that [unauthorized access/change] occurred.
Impact: [concrete business/security impact]
Suggested fix: Enforce server-side authorization for [object/function/property] on every request.
```

### Fast checklist

- [ ] Tested logged out, low role, high role, same tenant, different tenant where relevant.
- [ ] Changed one variable at a time.
- [ ] Used only controlled accounts/data.
- [ ] Captured before/after evidence.
- [ ] Explained why this is more than informative.


<div style="page-break-after: always;"></div>

## Page 50: Default Credentials and Exposed Admin Consoles

**VRT alignment:** Authentication / Security Misconfiguration  
**Best auth state:** Unauthenticated login surfaces; strict program rules

### Why this is worth testing

Admin consoles are high impact if default creds or no auth are present, but brute force is not allowed.

### Manual test procedure

1. Identify in-scope admin panels.
2. Check no-auth access and obvious setup wizard exposure.
3. Use only documented default credentials if policy permits and only once or twice.
4. Do not brute force.
5. If login succeeds, stop and report; do not browse sensitive data.


### Tools that help without replacing manual work

Browser, Burp, vendor documentation.

### Evidence that usually proves impact

Admin access, setup takeover, exposed management UI, configuration compromise.

### Common false positives / informative-only cases

No password spraying, brute forcing, or credential stuffing. A login page alone is not a vulnerability.

### Report skeleton

```text
Title: Default Credentials and Exposed Admin Consoles allows [unauthorized action/data] in [asset/feature]
Asset: https://target.example/path
Prerequisites: Account A [role], Account B [role], both controlled by researcher
Steps:
1. Create controlled object/data as Account B.
2. Capture the vulnerable request as Account A.
3. Modify [exact field] from [A value] to [B value].
4. Send the request and observe [response/side effect].
5. Confirm in Account B UI that [unauthorized access/change] occurred.
Impact: [concrete business/security impact]
Suggested fix: Enforce server-side authorization for [object/function/property] on every request.
```

### Fast checklist

- [ ] Tested logged out, low role, high role, same tenant, different tenant where relevant.
- [ ] Changed one variable at a time.
- [ ] Used only controlled accounts/data.
- [ ] Captured before/after evidence.
- [ ] Explained why this is more than informative.


<div style="page-break-after: always;"></div>

## Page 51: API Versioning and Deprecated Endpoint Authorization Gaps

**VRT alignment:** Improper Inventory Management / Broken Access Control  
**Best auth state:** Both; authenticated API usually

### Why this is worth testing

Old endpoints may keep weaker authorization, hidden fields, or legacy business rules.

### Manual test procedure

1. Find `/v1`, `/v2`, beta, mobile, internal, legacy routes in JS/docs/mobile traffic.
2. Repeat current endpoint tests against old versions.
3. Compare fields and auth behavior.
4. Check if deprecated endpoints still accept writes.
5. Test low role vs admin behavior.


### Tools that help without replacing manual work

Burp sitemap, DevTools, source maps, API docs, Postman.

### Evidence that usually proves impact

Old API allows BOLA/BFLA/mass assignment, exposes hidden fields, bypasses verification, or accepts deprecated auth tokens.

### Common false positives / informative-only cases

Deprecated endpoint existence alone is not a bug unless behavior is vulnerable.

### Report skeleton

```text
Title: API Versioning and Deprecated Endpoint Authorization Gaps allows [unauthorized action/data] in [asset/feature]
Asset: https://target.example/path
Prerequisites: Account A [role], Account B [role], both controlled by researcher
Steps:
1. Create controlled object/data as Account B.
2. Capture the vulnerable request as Account A.
3. Modify [exact field] from [A value] to [B value].
4. Send the request and observe [response/side effect].
5. Confirm in Account B UI that [unauthorized access/change] occurred.
Impact: [concrete business/security impact]
Suggested fix: Enforce server-side authorization for [object/function/property] on every request.
```

### Fast checklist

- [ ] Tested logged out, low role, high role, same tenant, different tenant where relevant.
- [ ] Changed one variable at a time.
- [ ] Used only controlled accounts/data.
- [ ] Captured before/after evidence.
- [ ] Explained why this is more than informative.


<div style="page-break-after: always;"></div>

## Page 52: Mobile API and Thick Client Assumption Bugs

**VRT alignment:** API Security / Sensitive Data Exposure / Access Control  
**Best auth state:** Authenticated mobile flows; only in-scope apps

### Why this is worth testing

Mobile apps often expose API endpoints and client secrets, but the real bugs are server trust assumptions.

### Manual test procedure

1. Proxy mobile traffic if allowed.
2. Look for hidden endpoints, feature flags, environment URLs, API keys.
3. Replay mobile API requests without mobile-only headers.
4. Change device/user/tenant IDs.
5. Check if client-side checks enforce subscription, role, or platform.


### Tools that help without replacing manual work

Burp mobile proxy, emulator, jadx/apktool only if allowed, Frida only in labs/where permitted.

### Evidence that usually proves impact

Server trusts client flags, hidden APIs expose data, mobile-only endpoint lacks authz, hardcoded secret grants access.

### Common false positives / informative-only cases

Hardcoded public API keys are often informative unless they grant unauthorized access or cost impact.

### Report skeleton

```text
Title: Mobile API and Thick Client Assumption Bugs allows [unauthorized action/data] in [asset/feature]
Asset: https://target.example/path
Prerequisites: Account A [role], Account B [role], both controlled by researcher
Steps:
1. Create controlled object/data as Account B.
2. Capture the vulnerable request as Account A.
3. Modify [exact field] from [A value] to [B value].
4. Send the request and observe [response/side effect].
5. Confirm in Account B UI that [unauthorized access/change] occurred.
Impact: [concrete business/security impact]
Suggested fix: Enforce server-side authorization for [object/function/property] on every request.
```

### Fast checklist

- [ ] Tested logged out, low role, high role, same tenant, different tenant where relevant.
- [ ] Changed one variable at a time.
- [ ] Used only controlled accounts/data.
- [ ] Captured before/after evidence.
- [ ] Explained why this is more than informative.


<div style="page-break-after: always;"></div>

## Page 53: Webhook and Integration Security Bugs

**VRT alignment:** Business Logic / SSRF / Access Control / Sensitive Data Exposure  
**Best auth state:** Authenticated integrations

### Why this is worth testing

Webhooks and integrations cross trust boundaries and often process URLs, secrets, signatures, events, and tenants.

### Manual test procedure

1. Create webhook as Account A and B.
2. Test cross-tenant webhook read/update/delete.
3. Check whether webhook secret is exposed after creation.
4. Test SSRF callback URL restrictions safely.
5. Check signature validation and event replay in your integration only.


### Tools that help without replacing manual work

Webhook.site/interactsh, Burp, test integration receiver.

### Evidence that usually proves impact

Exfiltration of events, SSRF via webhook URL, unauthorized webhook modification, secret exposure, replay of signed events.

### Common false positives / informative-only cases

Do not send events to third-party targets or spam webhook deliveries.

### Report skeleton

```text
Title: Webhook and Integration Security Bugs allows [unauthorized action/data] in [asset/feature]
Asset: https://target.example/path
Prerequisites: Account A [role], Account B [role], both controlled by researcher
Steps:
1. Create controlled object/data as Account B.
2. Capture the vulnerable request as Account A.
3. Modify [exact field] from [A value] to [B value].
4. Send the request and observe [response/side effect].
5. Confirm in Account B UI that [unauthorized access/change] occurred.
Impact: [concrete business/security impact]
Suggested fix: Enforce server-side authorization for [object/function/property] on every request.
```

### Fast checklist

- [ ] Tested logged out, low role, high role, same tenant, different tenant where relevant.
- [ ] Changed one variable at a time.
- [ ] Used only controlled accounts/data.
- [ ] Captured before/after evidence.
- [ ] Explained why this is more than informative.


<div style="page-break-after: always;"></div>

## Page 54: PDF, CSV, Spreadsheet, and Report Generation Bugs

**VRT alignment:** Injection / SSRF / Data Exposure / Business Logic  
**Best auth state:** Authenticated exports/reports

### Why this is worth testing

Report generators combine templates, HTML rendering, server-side fetches, formulas, and sensitive data aggregation.

### Manual test procedure

1. Add markers to fields rendered in PDF/CSV.
2. Check CSV formula injection only with harmless formula marker.
3. Check server-side HTML/PDF renderer for SSRF using controlled URL if allowed.
4. Test export access control across accounts.
5. Check if exports include hidden fields.


### Tools that help without replacing manual work

Burp, spreadsheet viewer in safe mode, interactsh, PDF metadata tools.

### Evidence that usually proves impact

Stored XSS in generated documents, CSV formula injection, SSRF by renderer, cross-tenant data export, hidden data leakage.

### Common false positives / informative-only cases

Do not craft formulas that execute commands or exfiltrate real data. Use harmless markers.

### Report skeleton

```text
Title: PDF, CSV, Spreadsheet, and Report Generation Bugs allows [unauthorized action/data] in [asset/feature]
Asset: https://target.example/path
Prerequisites: Account A [role], Account B [role], both controlled by researcher
Steps:
1. Create controlled object/data as Account B.
2. Capture the vulnerable request as Account A.
3. Modify [exact field] from [A value] to [B value].
4. Send the request and observe [response/side effect].
5. Confirm in Account B UI that [unauthorized access/change] occurred.
Impact: [concrete business/security impact]
Suggested fix: Enforce server-side authorization for [object/function/property] on every request.
```

### Fast checklist

- [ ] Tested logged out, low role, high role, same tenant, different tenant where relevant.
- [ ] Changed one variable at a time.
- [ ] Used only controlled accounts/data.
- [ ] Captured before/after evidence.
- [ ] Explained why this is more than informative.


<div style="page-break-after: always;"></div>

## Page 55: Search, Filter, Sort, and Pagination Edge Cases

**VRT alignment:** Injection / Access Control / Data Exposure  
**Best auth state:** Both; authenticated data tables are high-yield

### Why this is worth testing

Search endpoints frequently accept raw filters, sort fields, include parameters, and pagination tokens.

### Manual test procedure

1. Inspect filter JSON and query params.
2. Try adding `include=private`, `fields=*`, `tenantId`, `ownerId`, `isDeleted`, `status`.
3. Test sort/order fields for SQLi-like behavior safely.
4. Test pagination cursor reuse across users.
5. Compare list endpoint vs detail endpoint authorization.


### Tools that help without replacing manual work

Burp, jq, Comparer.

### Evidence that usually proves impact

Hidden records exposed, deleted/private records listed, cross-tenant search, injection in sort field, cursor leaks another account data.

### Common false positives / informative-only cases

Do not enumerate real user data; use owned test records.

### Report skeleton

```text
Title: Search, Filter, Sort, and Pagination Edge Cases allows [unauthorized action/data] in [asset/feature]
Asset: https://target.example/path
Prerequisites: Account A [role], Account B [role], both controlled by researcher
Steps:
1. Create controlled object/data as Account B.
2. Capture the vulnerable request as Account A.
3. Modify [exact field] from [A value] to [B value].
4. Send the request and observe [response/side effect].
5. Confirm in Account B UI that [unauthorized access/change] occurred.
Impact: [concrete business/security impact]
Suggested fix: Enforce server-side authorization for [object/function/property] on every request.
```

### Fast checklist

- [ ] Tested logged out, low role, high role, same tenant, different tenant where relevant.
- [ ] Changed one variable at a time.
- [ ] Used only controlled accounts/data.
- [ ] Captured before/after evidence.
- [ ] Explained why this is more than informative.


<div style="page-break-after: always;"></div>

## Page 56: Method Override, Verb Tampering, and Content-Type Confusion

**VRT alignment:** Broken Access Control / Business Logic  
**Best auth state:** Both; authenticated APIs

### Why this is worth testing

Frameworks and proxies may route or authorize by method/content-type inconsistently.

### Manual test procedure

1. Try `GET` vs `POST` vs `PUT` vs `PATCH` vs `DELETE` on same route.
2. Check `X-HTTP-Method-Override` and `_method` fields only if observed or framework suggests.
3. Change JSON to form-urlencoded or multipart.
4. Remove content-type or use unusual casing.
5. Verify state changes and authz behavior.


### Tools that help without replacing manual work

Burp Repeater, curl.

### Evidence that usually proves impact

Bypass CSRF, bypass route-level auth, perform blocked action, access hidden method.

### Common false positives / informative-only cases

Do not claim bug for `OPTIONS` listing methods unless an unsafe method is exploitable.

### Report skeleton

```text
Title: Method Override, Verb Tampering, and Content-Type Confusion allows [unauthorized action/data] in [asset/feature]
Asset: https://target.example/path
Prerequisites: Account A [role], Account B [role], both controlled by researcher
Steps:
1. Create controlled object/data as Account B.
2. Capture the vulnerable request as Account A.
3. Modify [exact field] from [A value] to [B value].
4. Send the request and observe [response/side effect].
5. Confirm in Account B UI that [unauthorized access/change] occurred.
Impact: [concrete business/security impact]
Suggested fix: Enforce server-side authorization for [object/function/property] on every request.
```

### Fast checklist

- [ ] Tested logged out, low role, high role, same tenant, different tenant where relevant.
- [ ] Changed one variable at a time.
- [ ] Used only controlled accounts/data.
- [ ] Captured before/after evidence.
- [ ] Explained why this is more than informative.


<div style="page-break-after: always;"></div>

## Page 57: Referer, Token, and Link Leakage

**VRT alignment:** Sensitive Data Exposure / Authentication  
**Best auth state:** Both; reset/OAuth/invite/download links

### Why this is worth testing

Tokens in URLs can leak to third parties via Referer headers, logs, analytics, redirects, and external resources.

### Manual test procedure

1. Identify URLs containing reset, invite, OAuth, export, magic login, or download tokens.
2. Check pages for external images/scripts/links loaded while token is in URL.
3. Check redirect chains and Referer policy.
4. Use your own token and controlled external endpoint.
5. Verify whether leaked token is still valid.


### Tools that help without replacing manual work

Burp, browser DevTools, controlled web server/interactsh.

### Evidence that usually proves impact

Password reset/invite/OAuth/export token leaked to third party, enabling account takeover or data access.

### Common false positives / informative-only cases

Do not use real tokens. A token in URL is not enough unless leakage or unsafe lifetime/binding is shown.

### Report skeleton

```text
Title: Referer, Token, and Link Leakage allows [unauthorized action/data] in [asset/feature]
Asset: https://target.example/path
Prerequisites: Account A [role], Account B [role], both controlled by researcher
Steps:
1. Create controlled object/data as Account B.
2. Capture the vulnerable request as Account A.
3. Modify [exact field] from [A value] to [B value].
4. Send the request and observe [response/side effect].
5. Confirm in Account B UI that [unauthorized access/change] occurred.
Impact: [concrete business/security impact]
Suggested fix: Enforce server-side authorization for [object/function/property] on every request.
```

### Fast checklist

- [ ] Tested logged out, low role, high role, same tenant, different tenant where relevant.
- [ ] Changed one variable at a time.
- [ ] Used only controlled accounts/data.
- [ ] Captured before/after evidence.
- [ ] Explained why this is more than informative.


<div style="page-break-after: always;"></div>

## Page 58: Email, Notification, and Template Injection

**VRT alignment:** Injection / Business Logic / Sensitive Data Exposure  
**Best auth state:** Authenticated workflows that send messages

### Why this is worth testing

Email templates render user-controlled names, org names, filenames, and comments in contexts that may be HTML, links, or headers.

### Manual test procedure

1. Place marker in display name/org/file/comment fields.
2. Trigger email/notification to your second account.
3. Check HTML escaping, link injection, header injection, and token placement.
4. Test whether attacker can alter destination, subject, or link target.
5. Use harmless markers only.


### Tools that help without replacing manual work

Test mailboxes, Burp, raw email viewer.

### Evidence that usually proves impact

HTML injection in trusted email, token leakage, link manipulation, notification spoofing, header injection where exploitable.

### Common false positives / informative-only cases

Do not send payloads to real users or staff. Email spoofing without security impact may be low.

### Report skeleton

```text
Title: Email, Notification, and Template Injection allows [unauthorized action/data] in [asset/feature]
Asset: https://target.example/path
Prerequisites: Account A [role], Account B [role], both controlled by researcher
Steps:
1. Create controlled object/data as Account B.
2. Capture the vulnerable request as Account A.
3. Modify [exact field] from [A value] to [B value].
4. Send the request and observe [response/side effect].
5. Confirm in Account B UI that [unauthorized access/change] occurred.
Impact: [concrete business/security impact]
Suggested fix: Enforce server-side authorization for [object/function/property] on every request.
```

### Fast checklist

- [ ] Tested logged out, low role, high role, same tenant, different tenant where relevant.
- [ ] Changed one variable at a time.
- [ ] Used only controlled accounts/data.
- [ ] Captured before/after evidence.
- [ ] Explained why this is more than informative.


<div style="page-break-after: always;"></div>

## Page 59: SAML/SSO Configuration and Tenant Binding Bugs

**VRT alignment:** Authentication / SSO / Access Control  
**Best auth state:** Enterprise/tenant auth flows; only where accounts/config are allowed

### Why this is worth testing

SAML and enterprise SSO flows can confuse tenant, issuer, audience, email, and role mapping.

### Manual test procedure

1. Use only your own test IdP/tenant where permitted.
2. Check whether SSO login is bound to correct tenant/domain.
3. Test account linking and email verification assumptions.
4. Check role/group mapping from claims.
5. Check logout/session behavior across SSO/local auth.


### Tools that help without replacing manual work

SAML-tracer, Burp, test IdP, browser profiles.

### Evidence that usually proves impact

Login to wrong tenant, account takeover via unverified email claim, role escalation through group claim, SSO bypass.

### Common false positives / informative-only cases

Do not tamper with real enterprise tenants. Do not forge signatures against production unless explicitly permitted.

### Report skeleton

```text
Title: SAML/SSO Configuration and Tenant Binding Bugs allows [unauthorized action/data] in [asset/feature]
Asset: https://target.example/path
Prerequisites: Account A [role], Account B [role], both controlled by researcher
Steps:
1. Create controlled object/data as Account B.
2. Capture the vulnerable request as Account A.
3. Modify [exact field] from [A value] to [B value].
4. Send the request and observe [response/side effect].
5. Confirm in Account B UI that [unauthorized access/change] occurred.
Impact: [concrete business/security impact]
Suggested fix: Enforce server-side authorization for [object/function/property] on every request.
```

### Fast checklist

- [ ] Tested logged out, low role, high role, same tenant, different tenant where relevant.
- [ ] Changed one variable at a time.
- [ ] Used only controlled accounts/data.
- [ ] Captured before/after evidence.
- [ ] Explained why this is more than informative.


<div style="page-break-after: always;"></div>

## Page 60: Access Control in Export, Import, and Bulk Actions

**VRT alignment:** Broken Access Control / Sensitive Data Exposure  
**Best auth state:** Authenticated

### Why this is worth testing

Bulk endpoints often skip per-object authorization for speed and are easy to overlook.

### Manual test procedure

1. Create objects in A and B.
2. Use bulk export/update/delete endpoint with mixed IDs from both accounts.
3. Check whether server processes unauthorized IDs silently.
4. Test CSV import with ownerId/tenantId/status fields.
5. Check asynchronous job result access control.


### Tools that help without replacing manual work

Burp, CSV editor, jq, browser profiles.

### Evidence that usually proves impact

Cross-tenant export, unauthorized bulk modification/deletion, import into another tenant, job result leakage.

### Common false positives / informative-only cases

Use disposable objects only. Do not bulk-delete real data.

### Report skeleton

```text
Title: Access Control in Export, Import, and Bulk Actions allows [unauthorized action/data] in [asset/feature]
Asset: https://target.example/path
Prerequisites: Account A [role], Account B [role], both controlled by researcher
Steps:
1. Create controlled object/data as Account B.
2. Capture the vulnerable request as Account A.
3. Modify [exact field] from [A value] to [B value].
4. Send the request and observe [response/side effect].
5. Confirm in Account B UI that [unauthorized access/change] occurred.
Impact: [concrete business/security impact]
Suggested fix: Enforce server-side authorization for [object/function/property] on every request.
```

### Fast checklist

- [ ] Tested logged out, low role, high role, same tenant, different tenant where relevant.
- [ ] Changed one variable at a time.
- [ ] Used only controlled accounts/data.
- [ ] Captured before/after evidence.
- [ ] Explained why this is more than informative.


<div style="page-break-after: always;"></div>

## Page 61: Asynchronous Job and Queue Result IDOR

**VRT alignment:** Broken Access Control / Sensitive Data Exposure  
**Best auth state:** Authenticated; reports/exports/import jobs

### Why this is worth testing

Async jobs create IDs for status and results. These often have weaker checks than original action.

### Manual test procedure

1. Start export/report/import as Account B.
2. Capture job ID/status/result URL.
3. Request with Account A.
4. Check direct file URL logged out.
5. Test cancellation/retry/download endpoints.


### Tools that help without replacing manual work

Burp, browser profiles, jq.

### Evidence that usually proves impact

User can download another user’s export, see job status, cancel jobs, or retrieve import errors containing sensitive data.

### Common false positives / informative-only cases

Do not create large exports. Use small controlled datasets.

### Report skeleton

```text
Title: Asynchronous Job and Queue Result IDOR allows [unauthorized action/data] in [asset/feature]
Asset: https://target.example/path
Prerequisites: Account A [role], Account B [role], both controlled by researcher
Steps:
1. Create controlled object/data as Account B.
2. Capture the vulnerable request as Account A.
3. Modify [exact field] from [A value] to [B value].
4. Send the request and observe [response/side effect].
5. Confirm in Account B UI that [unauthorized access/change] occurred.
Impact: [concrete business/security impact]
Suggested fix: Enforce server-side authorization for [object/function/property] on every request.
```

### Fast checklist

- [ ] Tested logged out, low role, high role, same tenant, different tenant where relevant.
- [ ] Changed one variable at a time.
- [ ] Used only controlled accounts/data.
- [ ] Captured before/after evidence.
- [ ] Explained why this is more than informative.


<div style="page-break-after: always;"></div>

## Page 62: Audit Log, Activity Feed, and Notification Data Exposure

**VRT alignment:** Sensitive Data Exposure / Broken Access Control  
**Best auth state:** Authenticated tenant/member roles

### Why this is worth testing

Logs and feeds may expose object names, emails, tokens, internal IDs, actor data, or cross-tenant events.

### Manual test procedure

1. Generate unique actions in Account B/Tenant B.
2. Check whether Account A/Tenant A can list or search logs.
3. Change filters and date ranges.
4. Check low-role vs admin log access.
5. Check notification APIs and WebSocket feeds.


### Tools that help without replacing manual work

Burp, jq, browser profiles.

### Evidence that usually proves impact

Cross-tenant/user activity leakage, sensitive event details, emails, object names, IPs, tokens, internal URLs.

### Common false positives / informative-only cases

Do not report audit log existence or your own logs as a bug.

### Report skeleton

```text
Title: Audit Log, Activity Feed, and Notification Data Exposure allows [unauthorized action/data] in [asset/feature]
Asset: https://target.example/path
Prerequisites: Account A [role], Account B [role], both controlled by researcher
Steps:
1. Create controlled object/data as Account B.
2. Capture the vulnerable request as Account A.
3. Modify [exact field] from [A value] to [B value].
4. Send the request and observe [response/side effect].
5. Confirm in Account B UI that [unauthorized access/change] occurred.
Impact: [concrete business/security impact]
Suggested fix: Enforce server-side authorization for [object/function/property] on every request.
```

### Fast checklist

- [ ] Tested logged out, low role, high role, same tenant, different tenant where relevant.
- [ ] Changed one variable at a time.
- [ ] Used only controlled accounts/data.
- [ ] Captured before/after evidence.
- [ ] Explained why this is more than informative.


<div style="page-break-after: always;"></div>

## Page 63: Feature Flags, Plans, Trials, and Entitlement Bypass

**VRT alignment:** Business Logic / Access Control  
**Best auth state:** Authenticated across plans/roles

### Why this is worth testing

Apps often enforce paid features in the client while APIs accept direct calls.

### Manual test procedure

1. Create free/trial and paid-equivalent if possible.
2. Capture paid-feature endpoint from allowed state or infer from JS.
3. Replay with free account.
4. Toggle feature flags in local storage/request body.
5. Check whether server enforces plan entitlement.


### Tools that help without replacing manual work

Burp, DevTools, source maps, browser profiles.

### Evidence that usually proves impact

Free user accesses paid features, exports, integrations, seats, support tiers, or quotas without entitlement.

### Common false positives / informative-only cases

Do not abuse paid resources. Stop at proof and use test data.

### Report skeleton

```text
Title: Feature Flags, Plans, Trials, and Entitlement Bypass allows [unauthorized action/data] in [asset/feature]
Asset: https://target.example/path
Prerequisites: Account A [role], Account B [role], both controlled by researcher
Steps:
1. Create controlled object/data as Account B.
2. Capture the vulnerable request as Account A.
3. Modify [exact field] from [A value] to [B value].
4. Send the request and observe [response/side effect].
5. Confirm in Account B UI that [unauthorized access/change] occurred.
Impact: [concrete business/security impact]
Suggested fix: Enforce server-side authorization for [object/function/property] on every request.
```

### Fast checklist

- [ ] Tested logged out, low role, high role, same tenant, different tenant where relevant.
- [ ] Changed one variable at a time.
- [ ] Used only controlled accounts/data.
- [ ] Captured before/after evidence.
- [ ] Explained why this is more than informative.


<div style="page-break-after: always;"></div>

## Page 64: Hidden Parameters and Server-Side Trust of Client State

**VRT alignment:** Business Logic / Access Control / Mass Assignment  
**Best auth state:** Both; mostly authenticated

### Why this is worth testing

Hidden parameters can unlock debug, admin, test, bypass, or alternate code paths.

### Manual test procedure

1. Compare UI requests with JS constants and API docs.
2. Add plausible params: `debug`, `preview`, `admin`, `bypass`, `test`, `force`, `internal`, `include`, `fields`.
3. Use Param Miner/Arjun lightly then verify manually.
4. Check response differences and side effects.
5. Focus on endpoints with business action.


### Tools that help without replacing manual work

Param Miner, Arjun, Burp Repeater, Comparer.

### Evidence that usually proves impact

Hidden parameter bypasses validation, exposes private fields, enables admin/debug behavior, changes object owner/tenant.

### Common false positives / informative-only cases

Do not report harmless debug messages without data/action impact.

### Report skeleton

```text
Title: Hidden Parameters and Server-Side Trust of Client State allows [unauthorized action/data] in [asset/feature]
Asset: https://target.example/path
Prerequisites: Account A [role], Account B [role], both controlled by researcher
Steps:
1. Create controlled object/data as Account B.
2. Capture the vulnerable request as Account A.
3. Modify [exact field] from [A value] to [B value].
4. Send the request and observe [response/side effect].
5. Confirm in Account B UI that [unauthorized access/change] occurred.
Impact: [concrete business/security impact]
Suggested fix: Enforce server-side authorization for [object/function/property] on every request.
```

### Fast checklist

- [ ] Tested logged out, low role, high role, same tenant, different tenant where relevant.
- [ ] Changed one variable at a time.
- [ ] Used only controlled accounts/data.
- [ ] Captured before/after evidence.
- [ ] Explained why this is more than informative.


<div style="page-break-after: always;"></div>

## Page 65: Error Handling With Sensitive Data or Control Impact

**VRT alignment:** Sensitive Data Exposure / Security Misconfiguration  
**Best auth state:** Both

### Why this is worth testing

Stack traces are often informative, but become reportable when they leak secrets, source, SQL queries with data, tokens, paths, or enable exploitation.

### Manual test procedure

1. Trigger harmless validation errors.
2. Check stack traces for secrets, credentials, file paths, internal hostnames, SQL with private data.
3. Check verbose errors on auth, upload, import, and payment flows.
4. See if error reveals object existence across accounts.
5. Do not fuzz heavily.


### Tools that help without replacing manual work

Burp Repeater, Comparer.

### Evidence that usually proves impact

Secrets or sensitive data exposed, object enumeration with private IDs, exploitation aid for injection/path traversal.

### Common false positives / informative-only cases

Framework name, stack trace without sensitive details, or generic path disclosure is often low/informative.

### Report skeleton

```text
Title: Error Handling With Sensitive Data or Control Impact allows [unauthorized action/data] in [asset/feature]
Asset: https://target.example/path
Prerequisites: Account A [role], Account B [role], both controlled by researcher
Steps:
1. Create controlled object/data as Account B.
2. Capture the vulnerable request as Account A.
3. Modify [exact field] from [A value] to [B value].
4. Send the request and observe [response/side effect].
5. Confirm in Account B UI that [unauthorized access/change] occurred.
Impact: [concrete business/security impact]
Suggested fix: Enforce server-side authorization for [object/function/property] on every request.
```

### Fast checklist

- [ ] Tested logged out, low role, high role, same tenant, different tenant where relevant.
- [ ] Changed one variable at a time.
- [ ] Used only controlled accounts/data.
- [ ] Captured before/after evidence.
- [ ] Explained why this is more than informative.


<div style="page-break-after: always;"></div>

## Page 66: Daily Manual Hunting Workflow: 90-Minute Focus Blocks

A productive bug bounty day should not be random. Use focused blocks.

### Block 1: Map

- Choose one feature family: billing, invites, uploads, reports, auth, integrations, APIs.
- Use the UI normally and capture every request.
- Label object IDs and roles.
- Build a mini endpoint table.

### Block 2: Compare

- Repeat the same feature with Account B.
- Compare A/B requests and responses.
- Highlight object IDs, tenant IDs, role fields, status fields, and hidden fields.

### Block 3: Tamper

- Swap IDs.
- Replay admin requests as user.
- Remove tokens.
- Change workflow step order.
- Try old endpoint versions.

### Block 4: Prove

- Confirm with controlled data.
- Take screenshots and raw request/response evidence.
- Reduce PoC to the minimum reliable steps.
- Check scope and exclusions.

### Block 5: Report or discard

If impact is clear, report. If not, write a note: “tested X, no issue because Y.” This prevents repeating work and helps pattern recognition.


<div style="page-break-after: always;"></div>

## Page 67: Feature-by-Feature Manual Test Matrix

Use this table while exploring a new application.

| Feature | Best bugs to test | Evidence target |
|---|---|---|
| Login | SQLi, enumeration, rate limits, MFA bypass | Auth bypass or practical abuse |
| Signup | verification bypass, invite abuse, tenant claim | unverified access or account claim |
| Password reset | token reuse, token binding, expiry, leakage | controlled account reset bypass |
| Profile | mass assignment, stored XSS, email change | role/email/security state change |
| Teams/orgs | BFLA, invite role tampering, tenant escape | unauthorized member/admin action |
| Billing | price tamper, invoice IDOR, coupon abuse | underpayment or private invoice access |
| Files | upload XSS, public access, traversal | private file read or active content |
| Reports/exports | async job IDOR, overbroad export | cross-account export access |
| Webhooks | SSRF, secret exposure, cross-tenant edit | callback or unauthorized event control |
| Search | BOLA via filters, injection, hidden fields | private record listing |
| Admin | role bypass, method tamper | low user performs admin action |
| API docs | hidden endpoints, deprecated routes | exploitable old route |
| GraphQL | resolver auth, nested fields, mutations | unauthorized field/action |
| WebSocket | subscription auth, message tamper | unauthorized stream/message |


<div style="page-break-after: always;"></div>

## Page 68: Safe Payload and Marker Strategy

Payloads should identify context and prove control without harming the target.

### Unique markers

Use markers that are easy to search and unlikely to collide:

```text
bbtest-20260505-idor-invoice-A
bbtest-20260505-xss-profile-name
bbtest-20260505-upload-svg
```

### XSS proof payloads

Prefer harmless browser-visible proof in your own account:

```html
"><svg onload=print()>
<img src=x onerror=print()>
```

Use only in isolated contexts and remove after testing.

### SQLi probes

Use read-only differential probes and avoid dangerous broad conditions on state-changing endpoints:

```text
'
"
')
true/false boolean comparison on read-only search
small time delay only if allowed
```

### SSTI probes

Use math-only probes first, not command execution:

```text
{{7*7}}
${7*7}
<%= 7*7 %>
```

### SSRF/XXE callback

Use your controlled callback domain. Do not target internal hosts unless the program explicitly permits it.

### File upload probes

Use harmless text, image, SVG, or metadata markers. Do not upload web shells, malware, or payloads intended to persist.


<div style="page-break-after: always;"></div>

## Page 69: Writing High-Signal Bug Bounty Reports

A strong report is short, reproducible, and impact-focused.

### Required parts

1. **Title:** Include the vulnerable feature and impact.
2. **Summary:** One paragraph: who can do what they should not be able to do.
3. **Scope:** Asset and account roles used.
4. **Steps to reproduce:** Exact, numbered, minimal.
5. **Raw request/response:** Redact secrets but keep IDs and paths needed to reproduce.
6. **Impact:** Tie to data sensitivity or unauthorized action.
7. **Evidence:** Screenshots of controlled data, not real user data.
8. **Suggested fix:** Server-side authorization/validation, token binding, state machine enforcement, output encoding, etc.
9. **Cleanup:** Mention test objects removed or available for validation.

### Bad title vs good title

Bad: `IDOR found`  
Good: `Cross-tenant invoice export IDOR lets a member of Tenant A download Tenant B invoices`

Bad: `CORS issue`  
Good: `Credentialed CORS origin reflection allows attacker origin to read authenticated API key metadata`

Bad: `XSS`  
Good: `Stored XSS in support ticket title executes in support-agent view and can perform agent actions`


<div style="page-break-after: always;"></div>

## Page 70: Retesting and Chaining Method

Not every low-hanging issue pays alone. Some become serious when chained.

### Useful chains

- Open redirect → OAuth code leak → account takeover.
- HTML injection → Referer leak of reset token → account takeover.
- CORS misconfig → read CSRF token → state-changing action.
- IDOR read → access invitation token → tenant join.
- Source map route discovery → hidden admin endpoint → BFLA.
- File upload SVG → stored XSS → account action as viewer.
- Web cache poisoning → stored XSS for public users.
- Rate limit missing on OTP → MFA bypass only if OTP entropy and attempts make bypass practical.
- Mass assignment role change → admin endpoint access.
- Password reset token not invalidated → session takeover after email change.

### Chain discipline

Document each link separately, then show the combined impact. Do not force a chain if one link is weak or unrealistic. Triage teams reward clear, minimal chains more than dramatic but brittle stories.


<div style="page-break-after: always;"></div>

## Page 71: Manual Notes Template for Each Target

Copy this into your notes for every new program.

```markdown
# Target notes: [program]

## Policy summary
- Scope:
- Exclusions:
- Test account rules:
- Rate limits:
- Forbidden classes:

## Identity matrix
- A1 owner/admin:
- A2 normal:
- B1 other tenant owner:
- B2 other tenant member:
- Guest/logged out:

## Assets
| Asset | Auth | Tech | Interesting routes | Notes |
|---|---|---|---|---|

## Object IDs
| Object | A ID | B ID | Endpoint | Tested? |
|---|---|---|---|---|

## Findings in progress
| Idea | Evidence | Missing proof | Next step |
|---|---|---|---|

## Things tested and rejected
| Test | Result | Why not a bug |
|---|---|---|
```


<div style="page-break-after: always;"></div>

## Page 72: Quick Decision Tree: What Should I Test Next?

### If you see object IDs

Test BOLA/IDOR read, write, delete, list, export, async job, nested tenant/object pairs.

### If you see roles

Test BFLA, role mass assignment, invite role tampering, admin routes, hidden GraphQL mutations.

### If you see tokens

Test lifetime, reuse, binding, leakage, Referer, redirect chains, logout/password-change invalidation.

### If you see URLs as input

Test SSRF callback, redirect validation, image import, PDF rendering, webhook restrictions.

### If you see file upload

Test file access control, content type, active content, filename traversal, overwrite, processing side effects.

### If you see payment/business action

Test quantity/price/currency/discount/plan/status tampering, workflow step skipping, race conditions.

### If you see JavaScript-heavy SPA

Search source maps, route names, hidden APIs, DOM XSS sources/sinks, feature flags, API versions.

### If you see GraphQL

Test introspection as recon, then resolver authorization with A/B IDs and roles.

### If you see cache headers

Test cache deception on private pages and poisoning on public cached pages with harmless markers.


<div style="page-break-after: always;"></div>

## Page 73: Final Pre-Submission Checklist

Before sending a report, check:

- [ ] The asset is in scope.
- [ ] The bug class is not excluded.
- [ ] The proof uses only accounts/data you control.
- [ ] The vulnerable request is included.
- [ ] You can reproduce from a clean session.
- [ ] You explained expected vs actual behavior.
- [ ] You showed concrete data/action impact.
- [ ] You avoided unnecessary exploitation.
- [ ] You redacted cookies, tokens, and secrets.
- [ ] You included cleanup details.
- [ ] You did not rely on scanner output alone.
- [ ] You did not report an informative-only issue as high severity.

### Impact wording formula

`A [role/auth state] user can [read/modify/trigger] [protected object/action] belonging to [other user/tenant/admin/business workflow] by [specific tamper], resulting in [security/business impact].`

Example:

`A normal workspace member can change the role of another member to owner by adding role=owner to the invite update API request, resulting in full workspace takeover.`


<div style="page-break-after: always;"></div>

## Page 74: Sources and Further Practice

The guide is a synthesized checklist based on practical bug bounty methodology and the following public references. Always check the live program policy and the current VRT before reporting.

- [Bugcrowd VRT](https://bugcrowd.com/vulnerability-rating-taxonomy)
- [Bugcrowd VRT GitHub](https://github.com/bugcrowd/vulnerability-rating-taxonomy)
- [OWASP WSTG](https://owasp.org/www-project-web-security-testing-guide/)
- [OWASP WSTG Business Logic](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/10-Business_Logic_Testing/)
- [OWASP Top 10 Broken Access Control](https://owasp.org/Top10/2021/A01_2021-Broken_Access_Control/)
- [OWASP API Security Top 10 2023](https://owasp.org/API-Security/editions/2023/en/0x11-t10/)
- [OWASP Forgot Password Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [PortSwigger IDOR Testing](https://portswigger.net/burp/documentation/desktop/testing-workflow/vulnerabilities/access-controls/testing-for-idors)
- [PortSwigger SQL Injection](https://portswigger.net/web-security/sql-injection)
- [PortSwigger XSS](https://portswigger.net/web-security/cross-site-scripting)
- [PortSwigger SSRF](https://portswigger.net/web-security/ssrf)
- [PortSwigger File Upload](https://portswigger.net/web-security/file-upload)
- [PortSwigger OAuth](https://portswigger.net/web-security/oauth)
- [PortSwigger JWT](https://portswigger.net/web-security/jwt)
- [Bugcrowd Automated vs Manual Testing](https://www.bugcrowd.com/blog/penetration-testing-automated-vs-manual-testing-methods/)
- [Bugcrowd IDOR Article](https://www.bugcrowd.com/blog/how-to-find-idor-insecure-direct-object-reference-vulnerabilities-for-large-bounty-rewards/)
- [Assetnote Recon](https://www.assetnote.io/resources/blog/the-art-of-recon-strategies-for-modern-asset-discovery)
- [Intigriti Bug Bytes](https://www.intigriti.com/researchers/blog/bug-bytes/bugbytes-28)


### How the sources were used

- Bugcrowd VRT: baseline severity language and the idea that priority changes with context.
- OWASP WSTG: broad testing categories, especially authentication, authorization, session management, and business logic.
- OWASP API Top 10: API-specific access control, object/property/function authorization, resource consumption, SSRF, and inventory issues.
- OWASP Cheat Sheets: secure expectations for password reset, authentication, and session handling.
- PortSwigger Web Security Academy: manual testing workflows and vulnerability-specific learning structure for access control, IDOR, SQLi, XSS, SSRF, file uploads, OAuth, and JWT.
- Bug bounty/practitioner writeups: emphasis on combining light automation for coverage with manual logic testing for higher-quality findings.

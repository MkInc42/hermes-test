# Backend Input and Threat Model Specification

Project: Internal phishing triage engine
Milestone: 1 backend specification and threat-model gate
Status: Authoritative baseline for implementation cards
Audience: backend, scanner, report-generation, and reviewer agents

## 1. Scope and operating model

This milestone defines a backend-first phishing triage system for internal use. It accepts suspicious email artifacts, raw URLs, OCR-derived text-message content, and screenshot evidence; normalizes them into a tenant-scoped job; runs safe, disposable analysis; stores finished jobs and artifacts in one Postgres database; and produces an evidence-backed analyst report.

The system is not a public SaaS scanner in this milestone. There is no public self-service portal, no anonymous scan endpoint, no customer-facing automated abuse workflow, and no capability to submit credentials, interact with phishing pages as a victim, or conduct offensive actions.

Required invariant from day one: every persisted job, artifact, normalized indicator, scan event, and report record is keyed by a per-customer UID/tenant key. The UID is not optional for storage. Anonymous or tenantless jobs may exist only as rejected intake attempts in operational logs, not as analyzable jobs.

## 2. Primary threat model

### 2.1 Assets protected

- Internal analyst workstation and browser profile safety.
- Company/source IP reputation.
- Customer email, message, screenshot, and metadata privacy.
- Postgres job/artifact database integrity.
- Scanner worker/container isolation boundary.
- Report credibility and evidence chain of custody.
- Tenant separation between customer UIDs.
- Secrets used by infrastructure, optional intelligence APIs, storage, and mail/report delivery.

### 2.2 Adversaries considered

- Phishing operators submitting or causing submission of malicious URLs, payloads, HTML, redirects, QR codes, attachments, or screenshot content.
- Customers or internal users accidentally submitting sensitive content or credentials in email/message artifacts.
- Abuse users attempting to use the engine as an open scanner, crawler, availability tester, redirect resolver, screenshot proxy, reputation oracle, or malware detonator.
- Web infrastructure that fingerprints analysts, attempts drive-by exploitation, serves browser exploits, or blocks/redirects based on network location.
- Multi-tenant data exposure caused by missing UID scoping, report generation bugs, or unsafe artifact URLs.

### 2.3 High-level safety position

The engine is defensive evidence collection, not exploitation. Collection must be bounded, attributable to an internal job, and reproducible. Scanner traffic should be disposable/containerized and designed to route only through a future Private Internet Access (PIA) VPN sidecar. The VPN protects internal IP exposure but is not the only safety control; browser isolation, timeouts, egress restrictions, credential suppression, fetch limits, and prohibited-action enforcement are required even when VPN routing exists.

## 3. Intake requirements and canonical input schema

### 3.1 Common job envelope

Every accepted job must have this envelope before analysis starts:

```json
{
  "tenant_uid": "cust_01HZY...",
  "source_type": "raw_url|email_artifact|ocr_text_message|screenshot_evidence|mixed_bundle",
  "submitted_by": {
    "actor_type": "internal_analyst|customer_delegate|automation",
    "display_name": "optional human-readable name",
    "contact": "optional email/handle",
    "submitted_at": "RFC3339 timestamp"
  },
  "case_reference": "optional customer ticket or internal case id",
  "customer_metadata": {
    "organization_name": "optional",
    "industry": "optional",
    "reported_brand": "optional",
    "recipient_region": "optional",
    "business_impact_notes": "optional"
  },
  "inputs": [],
  "consent_and_authorization": {
    "submitter_attests_authorized_to_share": true,
    "analysis_type": "defensive_phishing_triage",
    "no_credential_submission_acknowledged": true
  }
}
```

Validation rules:

- `tenant_uid` is required, immutable after creation, and must scope every database query and artifact lookup.
- `source_type` must match the submitted material; `mixed_bundle` is allowed when an email and screenshots/OCR text support the same incident.
- `submitted_at` is recorded by the server even if client supplied metadata includes another timestamp.
- Customer metadata is optional enrichment, never authorization by itself.
- Intake must reject or quarantine jobs missing required consent/authorization flags.
- Raw secrets, passwords, tokens, session cookies, access codes, or payment card data found in submitted content must be redacted from derived views and reports unless explicitly required as evidence, in which case only masked excerpts may appear.

### 3.2 Raw URL input

Raw URL input object:

```json
{
  "input_id": "uuid",
  "type": "raw_url",
  "original_value": "https://example.invalid/path?x=y",
  "received_context": "optional surrounding message text or analyst note",
  "source_label": "optional e.g. SMS link, email body link, QR decode",
  "normalization": {
    "trimmed_value": "string",
    "parsed_scheme": "http|https",
    "hostname": "string",
    "registered_domain": "string",
    "path_hash": "sha256",
    "query_hash": "sha256"
  }
}
```

Validation and handling:

- Accept `http` and `https` URLs only for live fetch lifecycle. Other schemes (`file`, `javascript`, `data`, `chrome`, `ftp`, `smb`, `mailto`, custom app links) are indicators only and must not be executed.
- Preserve the exact original value for evidence, but render reports with safe defanging by default.
- Normalize IDN/Punycode and mixed-case domains while preserving original string.
- Strip leading/trailing whitespace and control characters before parsing; preserve a hash of the original string.
- Enforce maximum URL length and reject inputs that exceed parser/resource limits rather than truncating silently.
- Do not automatically expand shortened URLs outside the controlled scanner lifecycle.

### 3.3 Forwarded email artifact/body/headers input

Email submission is a first-class intake path. Even though this milestone is backend-first, the eventual small frontend must support email submissions because original headers are required for complete analysis. Required frontend-compatible intake modes are:

- Drag-and-drop or upload of original message artifacts, preferring `.eml` and `.msg` whenever possible.
- Copy/paste fallback for raw headers plus body, or forwarded body text when the original artifact is unavailable.
- Explicit fidelity labeling so copy/paste or forwarded submissions are marked lower-confidence when full original headers are missing.

Backend handling must preserve raw original headers and body as immutable evidence, compute hashes over submitted artifacts/canonical pasted text, parse headers into derived records separately from preserved raw content, and carry fidelity/caveat fields into reporting.

Email artifact input object:

```json
{
  "input_id": "uuid",
  "type": "email_artifact",
  "artifact_format": "eml|msg|raw_headers|forwarded_body|mime_text",
  "original_filename": "optional",
  "artifact_sha256": "sha256",
  "received_headers_raw": "optional stored artifact reference",
  "body_raw_reference": "stored artifact reference",
  "parsed": {
    "message_id": "optional",
    "subject": "optional redacted string",
    "from": "optional address/display",
    "reply_to": "optional",
    "return_path": "optional",
    "to_count": 0,
    "date_header": "optional original date",
    "urls_extracted": [],
    "attachments": []
  }
}
```

Validation and handling:

- Prefer original `.eml` or `.msg` where available. Forwarded text is accepted but lower-confidence.
- Preserve full raw artifact as evidence with immutable hash.
- Parse headers defensively. Never trust `From`, `Date`, `Message-ID`, or `Received` values as truth without labeling source.
- Extract URLs and attachment metadata without executing scripts, loading remote images in analyst browser profiles, or rendering active content outside sandboxed scanner workers.
- Treat attachments as artifacts for metadata extraction only in this milestone unless a later card explicitly implements safe attachment detonation.
- Do not send auto-replies or interact with sender infrastructure.

### 3.4 OCR-derived text-message content input

OCR text-message input object:

```json
{
  "input_id": "uuid",
  "type": "ocr_text_message",
  "ocr_text": "raw OCR text from SMS/chat screenshot",
  "ocr_engine": "optional",
  "ocr_confidence": "optional numeric/string from source",
  "message_platform": "sms|imessage|whatsapp|telegram|signal|unknown|other",
  "sender_display": "optional redacted",
  "observed_timestamp": "optional user-visible timestamp",
  "urls_extracted": [],
  "phone_numbers_extracted": []
}
```

Validation and handling:

- OCR text is untrusted evidence and may contain recognition errors; reports must label extracted indicators as OCR-derived unless corroborated.
- Preserve line breaks and surrounding context because spacing affects URL reconstruction.
- Extract URLs, domains, phone numbers, brand names, and urgency/payment language for triage.
- Do not message, call, verify, or otherwise interact with phone numbers, handles, or chat accounts.
- Do not infer victim identity from screenshots beyond submitted context.

### 3.5 Screenshot evidence input

Screenshot evidence input object:

```json
{
  "input_id": "uuid",
  "type": "screenshot_evidence",
  "artifact_sha256": "sha256",
  "original_filename": "optional",
  "media_type": "image/png|image/jpeg|image/webp|application/pdf",
  "source_context": "email_screenshot|sms_screenshot|browser_screenshot|customer_uploaded|analyst_captured|unknown",
  "capture_timestamp": "optional",
  "ocr_reference": "optional derived text artifact",
  "visual_notes": "optional analyst or automated notes"
}
```

Validation and handling:

- Preserve original image/PDF bytes, hash, dimensions, and MIME type.
- Strip or quarantine embedded metadata before producing customer-facing copies, while preserving the original internally under tenant scope.
- OCR output must be stored as a derived artifact linked to the original screenshot.
- Screenshots may show PII, account balances, tokens, one-time codes, or private messages; derived reports must mask sensitive content unless specifically necessary for phishing evidence.

### 3.6 Optional customer metadata

Allowed metadata fields are for report context and tenant operations only:

- organization/customer display name
- tenant UID
- industry/vertical
- reporting contact or internal case owner
- customer ticket/case reference
- reported brand or impersonated service
- recipient geography/language
- business impact notes
- prior related case IDs under the same tenant

Metadata must not be used to loosen safety controls. A trusted customer or internal submitter cannot authorize prohibited actions such as credential submission, exploitation, bypassing access controls, spam, or broad crawling.

## 4. Storage and evidence model

### 4.1 Postgres persistence requirement

Finished jobs and artifacts must persist in one Postgres database from day one. Minimum logical tables/records:

- `tenants`: tenant UID, display name, retention tier, status.
- `jobs`: job ID, tenant UID, source type, submitter metadata, lifecycle state, timestamps, policy decisions.
- `input_artifacts`: immutable original artifacts, SHA-256, MIME/type, storage pointer, tenant UID, job ID.
- `derived_artifacts`: parsed headers, OCR output, screenshots captured by scanner, HTTP transcripts, redirect chains, DNS results, report files.
- `indicators`: URLs, domains, hostnames, IPs, email addresses, phone numbers, file hashes, QR-decoded values, all tenant/job scoped.
- `scan_events`: scanner actions, timestamps, tool/container identity, network route label, errors, blocked actions.
- `reports`: generated report artifact references, report version, redaction state, evidence manifest.

No object storage pointer, local file path, report URL, or API route may be resolvable without tenant UID scoping and authorization.

### 4.2 Chain of custody

For each original and derived artifact record:

- Store SHA-256 of exact bytes or canonical text.
- Store capture/ingest timestamp generated by the backend.
- Store source relationship: original submission, parser output, scanner output, analyst note, or generated report.
- Store tool/version/container image where applicable.
- Preserve raw values internally but defang and redact in rendered reports.
- Maintain immutable originals; corrections create new derived records, not overwrites.

## 5. Safe scanning rules

### 5.1 Scanner isolation

All live web analysis must run in disposable scanner workers/containers. Required design:

- One job or tightly bounded batch per disposable worker.
- No normal Chrome profile, no analyst desktop browser profile, no persistent cookies shared across jobs.
- Ephemeral browser user data directory destroyed after job completion.
- Read-only runtime where practical; writable scratch volume per job only.
- Network egress allowlisted to scanner needs; internal network ranges blocked by default.
- Future PIA VPN sidecar is the intended route for external HTTP/S traffic; scanner must be designed so all external fetches can be forced through that sidecar.
- DNS/HTTP logs emitted as evidence; route label recorded (for example `direct-dev`, `pia-sidecar-required`, `blocked-no-route`).

### 5.2 Browser and fetch behavior

Allowed:

- Passive DNS, WHOIS/RDAP, certificate transparency, reputation API lookups.
- Single-target HTTP/S fetches of submitted URL and same-flow redirects within configured depth.
- Screenshot capture of landing page in disposable browser without interaction.
- DOM text extraction, title, form/action inventory, visible brand claims, redirect chain capture.
- HTTP metadata collection: status, headers, TLS certificate metadata, final URL, server hints.
- Defanged report rendering and internal analyst notes.

Restricted and must be bounded:

- Redirect following: enforce max redirect count, max total elapsed time, and same-job evidence logging.
- Crawling: only shallow page resource observation required for evidence; no broad site spidering in this milestone.
- Form analysis: inventory field names/types/actions, but do not fill or submit.
- JavaScript execution: only in disposable browser; disable or block dangerous capabilities where practical.
- File downloads: metadata/hash only unless explicitly allowed by later safe-download handling.

Prohibited:

- Credential submission, fake login, MFA/OTP entry, payment-card entry, or use of real customer credentials.
- Exploitation, payload delivery, vulnerability scanning beyond passive/banner-safe collection, brute force, directory busting, or authentication bypass.
- Contacting victims, threat actors, phone numbers, chat accounts, registrars, hosts, or abuse desks automatically.
- Using the tool as an open public scanner, redirect expander, screenshot proxy, uptime monitor, spam tester, or DDoS/availability tester.
- Loading malicious content in a normal desktop Chrome profile or any profile with user cookies/secrets.
- Accessing local/internal RFC1918/link-local/metadata endpoints through submitted URLs.
- Circumventing WAF/anti-bot controls with stealth or evasion beyond normal defensive single-fetch collection.

### 5.3 SSRF and local-network controls

Before any live fetch:

- Resolve hostname and block private, loopback, link-local, multicast, reserved, carrier-grade NAT, and cloud metadata IP ranges.
- Re-check IP after redirects and DNS changes.
- Block non-HTTP/S schemes.
- Enforce port policy: default HTTP 80 and HTTPS 443; any other port requires explicit allowlist and logging.
- Disable access to local files, browser extension URLs, and host-mounted secrets.
- Treat URL parser ambiguity as deny/quarantine, not allow.

## 6. Scan lifecycle

Required lifecycle states:

1. `submitted`: intake received with tenant UID and raw materials.
2. `validated`: schema, authorization, file type, size, and safety checks passed.
3. `queued`: job accepted for disposable scanner.
4. `normalizing`: URL/header/OCR/artifact parsing and indicator extraction.
5. `policy_checked`: unsafe or prohibited targets/actions blocked before live fetch.
6. `scanning`: passive and bounded dynamic collection in disposable worker.
7. `analyzing`: enrichment, correlation, brand/social-engineering assessment, and confidence scoring.
8. `reporting`: evidence manifest and customer/internal report generation.
9. `completed`: report and artifacts persisted with hashes.
10. `blocked`: policy or safety control prevented one or more actions; report may still be produced from available evidence.
11. `failed`: technical failure; preserve partial evidence and error trail.
12. `expired`: retained metadata only after retention window if retention policy requires artifact deletion.

Each state transition must record timestamp, actor/tool, reason, and tenant/job scope. `blocked` is a valid safety outcome and must not be treated as failed analysis.

## 7. Minimum report evidence

Every finished report must include enough evidence for a DFIR-style narrative without exposing unnecessary sensitive data:

- Executive finding: benign/suspicious/phishing/malware-delivery/blocked-insufficient-evidence with confidence.
- Submitted evidence summary: source type(s), tenant/case reference, original artifact hashes, timestamps.
- Indicator table: defanged URLs/domains/IPs/email addresses/phone numbers/file hashes; note OCR-derived indicators separately.
- Delivery context for email cases: sender display/address, reply-to/return-path, received-chain observations, authentication results if available, extracted links/attachments.
- Infrastructure observations: DNS/RDAP/WHOIS where available, TLS certificate summary, hosting/CDN hints, redirect chain, final landing host.
- Page/brand observations: screenshot hash/reference, title/visible text, form inventory, impersonated brand, credential/payment request indicators.
- Safety controls applied: container worker ID, route label, blocked actions, redirect/fetch limits, no credential submission statement.
- TTP mapping: concise ATT&CK/behavioral mapping where appropriate, such as phishing link delivery, credential harvesting page, brand impersonation, link shortener/redirector use.
- Analyst caveats: OCR uncertainty, forwarded-email limitations, blocked dynamic collection, inaccessible page, geo/WAF variance.
- Recommended actions: block/monitor indicators, user notification guidance, credential reset only if entered, mailbox search terms, domain/reporting escalation if human-approved.

Reports must distinguish observed fact from inference. Screenshots and raw artifacts must be referenced by hash/artifact ID rather than embedded with unmasked PII by default.

## 8. Abuse boundaries and liability language

### 8.1 Required user-facing/internal attestation language

Submitter must attest:

- They are authorized to submit the material for defensive phishing triage.
- They will not use the service to scan third-party infrastructure unrelated to a suspicious message or case.
- They understand the system will not submit credentials, payments, OTPs, or forms.
- They understand analysis is best-effort and may be incomplete due to safety blocks, unavailable infrastructure, geofencing, WAF behavior, takedowns, or submitted-artifact limitations.
- They are responsible for legal/compliance review before external abuse reports or law-enforcement notifications.

### 8.2 Liability boundaries for generated reports

Reports must include language that:

- Findings are based on artifacts provided and passive/bounded observations at collection time.
- A phishing determination is not a legal attribution of the infrastructure owner, registrar, hosting provider, or impersonated brand.
- Recommendations are defensive guidance, not legal advice.
- Indicators may be shared internally according to customer agreement and retention/privacy policy; external sharing requires authorized human decision.
- Absence of malicious behavior during scan does not prove the URL or sender is safe.

## 9. Data retention and privacy expectations

Baseline retention policy to implement/configure:

- Original artifacts: retain for the customer-approved investigation window; default should be limited and configurable by tenant.
- Derived indicators and report metadata: retain longer for trend/correlation if allowed by customer agreement.
- Sensitive screenshots/email bodies: redact in reports; restrict raw access to authorized analysts.
- Secrets/credentials discovered in submissions: mask in UI/reports and mark artifact as sensitive.
- Tenant deletion/export: design records so tenant UID supports full export and deletion workflows.
- Audit logs: retain access and lifecycle events separately from artifact content where possible.
- Backups: ensure backup retention does not silently exceed customer data-retention commitments.

Privacy controls:

- Encrypt secrets at rest; use least-privilege DB roles/service credentials.
- Do not log raw email bodies, full URLs with sensitive query tokens, cookies, Authorization headers, or unmasked PII in application logs.
- Defang URLs in reports and notifications.
- Separate internal analyst report view from customer-safe rendered output.
- Require explicit tenant UID filter in application data-access layer and test for cross-tenant leakage.

## 10. Out of scope for this milestone

The following are intentionally out of scope unless later cards explicitly add safe, reviewed implementation:

- Public SaaS portal, anonymous scan submission, open API keys, or public scanner endpoint.
- Malware detonation, attachment sandboxing, exploit execution, or vulnerability scanning.
- Automated abuse reports to providers, registrars, hosts, impersonated brands, or law enforcement.
- Credential entry, payment entry, account takeover validation, fake victim interaction, or form submission.
- Broad crawling/spidering, directory brute forcing, subdomain takeover scanning, port scanning, or availability testing.
- Threat-actor attribution beyond evidence-backed campaign/infrastructure observations.
- Long-term customer case-management workflow beyond persisted jobs/artifacts/reports.
- Production PIA VPN implementation details beyond the design requirement that scanner egress can be forced through a VPN sidecar.
- Customer-facing remediation automation.

## 11. Implementation gates for downstream cards

A downstream implementation card must not pass review unless it demonstrates:

- Required tenant UID on job creation and all persisted records.
- Input validation for raw URL, email artifact, OCR text-message content, screenshot evidence, optional metadata, and consent/authorization flags.
- Artifact hashing and immutable original preservation.
- Disposable scanner worker/container design with no normal Chrome profile and no credential/form submission path.
- SSRF/local-network protections before live fetch.
- Scan lifecycle states and evidence logging.
- Postgres persistence for completed jobs and artifacts.
- Report generation with minimum evidence sections and redaction/defanging.
- Local verification evidence for safety checks.
- Review handoff using `kanban_request_review` with `reviewer=principal-reviewer`, unless a pre-created dependent review/QA child requires completion of the parent card to release it.

## 12. Open decisions for later milestones

These are intentionally left as future implementation decisions, not blockers for this specification:

- Exact database migration framework and ORM.
- Exact object storage strategy if artifacts outgrow Postgres-native storage/pointers.
- Exact PIA sidecar implementation and deployment topology.
- Whether reports are rendered as Markdown, HTML, PDF, or multiple formats.
- Customer-specific retention duration defaults.
- Optional enrichment provider list and API-key management pattern.

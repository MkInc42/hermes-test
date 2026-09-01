# Mark Mobile Mechanic.LLC — Landing Page Preview

**Status:** DRAFT-ONLY Preview. Not published, not sent, not deployed.

This directory contains a mobile-first static landing page mockup for
Mark Mobile Mechanic.LLC, built from Sales Sprint research artifacts.

## How to View

Open `index.html` directly in any modern browser:

```bash
# Navigate to the preview directory
cd landing-page-preview/

# Open on Linux
xdg-open index.html

# Or serve locally with Python (recommended for tel: links to work)
python3 -m http.server 8080
# Then visit http://localhost:8080
```

No server required for basic viewing — the page is pure HTML + CSS.
A local server helps `tel:` links behave properly on desktop.

## What This Preview Includes

- Hero with prominent click-to-call button
- "We come to you" / service area section
- Common mobile mechanic services grid
- Review/social proof summary (themed, no actual review text)
- Hours (observed schedule, marked for owner verification)
- Contact CTA with phone and address
- Covered On offer terms ($499 static website scope)

## Brand Palette

Used where appropriate from Covered On brand:
- Navy `#0a2740`
- Green `#1f7a5c`
- Gold `#c79a3e`
- Paper `#f3f6f4`

## What Was Intentionally Not Done

1. **No prospect-owned photos, reviews, or logos** — Every visual is
   placeholder text or Unicode icons. No real customer photos, review
   snippets, or business logo used. Owner consent is required before
   any of those appear on a live site.

2. **No outreach or publish action** — Nothing was sent, scheduled,
   or deployed. This is a local-only preview file.

3. **No booking system** — The base offer ($499) does not include
   booking, ecommerce, CRM, or any backend. Calls and texts are the
   only booking path.

4. **No ranking or revenue guarantees** — The offer details section
   explicitly disclaims ranking, revenue, and booking-volume claims.

5. **No JavaScript** — Pure HTML/CSS. No tracking, analytics, or
   third-party scripts.

6. **No owner-confirmed details** — Service-area boundaries, exact
   hours, service list, and tagline all need owner confirmation before
   the site goes live.

7. **No logo** — The prospect does not have a visible logo. The site
   uses the trade name as text only.

## Source Artifacts

This preview was built from the following files in the parent directory:

- `prospect-sheet.csv` — Prospect scoring and public data
- `offer-packet.md` — Covered On offer terms and positioning
- `static-site-brief.md` — Web-dev handoff brief
- `outreach-draft.md` — Draft outreach (never sent)
- `covered-on-ea-lead-packet.md` — EA routing packet
- `smoke-test-summary.md` — Full pipeline assessment

## Directory Structure

```
landing-page-preview/
  index.html       — Main landing page
  css/
    style.css      — Mobile-first stylesheet
  js/              — Reserved (empty; no JS used)
  README.md        — This file
```

## Next Steps

Before this can become a live site, the following must happen:

1. Owner consent for photos, reviews, and branding
2. Owner confirmation of service-area boundaries
3. Owner confirmation of hours and schedule
4. Owner approval or modification of service list
5. Domain registration and DNS setup
6. Final copy review and approval
7. Full build gate per Covered On workflow
# Tony Stucco mockup revision brief — v16

## Goal
Create a client-ready cleanup revision of the latest Tony Stucco local preview.

## Source files
- Current mockup: `/home/black/covered-on-prospects/tony-stucco/mockup-report/tony-stucco-client-share-mockups-v15.html`
- New output: `/home/black/covered-on-prospects/tony-stucco/mockup-report/tony-stucco-client-share-mockups-v16.html`
- Existing workspace: `/home/black/covered-on-prospects/tony-stucco/mockup-report/`

## Context
This is Covered On's first customer preview for Tony Stucco Service LLC. Do not deploy, publish, email, or contact Tony. Work only in the local preview files.

Business/service focus:
- Stucco repair / stucco plastering
- Residential exterior painting
- Residential jobs are always welcome
- Commercial exterior work is limited/select and available by request only
- Service corridor runs Jacksonville to Tampa, including Orlando, Ocala, Daytona Beach, and Lakeland

## Required fixes from TRIP + Corey review

### 1) Wire all primary CTAs
The current v15 primary CTAs still use dead `href="#"` placeholders.

Fix these so they go somewhere useful in-page or tel-based:
- Header `GET AN ESTIMATE`
- Hero `REQUEST AN ESTIMATE`
- Mid-page `TALK TO TONY ABOUT YOUR PROJECT`
- `SEE MORE PROJECTS`
- Bottom `REQUEST AN ESTIMATE`

Preferred approach:
- Conversion CTAs should link to the contact/final CTA section or a real contact anchor.
- Phone CTAs should use real `tel:` links where appropriate.
- Do not leave primary conversion buttons as `href="#"`.
- In-page nav anchors such as `#services`, `#projects`, `#about`, `#contact` are acceptable if the targets exist.

### 2) Fix masked/broken phone links
Corey found masked phone hrefs such as:
- `href="tel:+1239****8845"`

Visible phone appears as `(239) 350-8845`. Use a valid tel URL for that visible number unless file evidence proves a different confirmed number.

Expected format:
- `tel:+12393508845`

Confirm every phone link is valid and consistent.

### 3) Fix mobile horizontal overflow
TRIP verified mobile overflow:
- viewport: 390px
- document scrollWidth: 423px
- offender: `.header-actions` / `.btn-estimate`

Fix the mobile header so there is no horizontal scroll at common mobile widths.

Acceptable approaches:
- allow wrapping;
- shrink/stack header actions under narrow breakpoints;
- shorten mobile CTA text;
- make the phone/button layout responsive;
- avoid clipping text or creating unusable tap targets.

Verification must prove at 390px and preferably 375px: `document.documentElement.scrollWidth <= window.innerWidth + 1`.

### 4) Rewrite stale first-body paragraph
The section headed `Your exterior. Handled right.` still contains older audience wording:
- homeowner
- property manager
- general contractor

This overweights audiences that are not the current focus and conflicts with the dedicated residential/commercial section later.

Rewrite this first-body copy so it is:
- homeowner/residential-first;
- short and direct;
- contractor-style;
- no fluffy agency language;
- no awkward stacked qualifiers;
- no em dashes;
- still mentions stucco repair, stucco plastering, exterior painting, and Florida conditions;
- commercial work only briefly if needed, and framed as limited/select work by request.

Also surface `Free estimates` visibly in the hero, CTA, or this first-body section. It currently exists in meta description only and should be visible to visitors.

### 5) Clean obvious placeholder behavior
Audit remaining `href="#"` values.
- Logo link may safely point to `#top` if a top anchor exists.
- Service/footer links should either point to valid in-page anchors or not look clickable.
- Do not leave obvious dead links that make the preview feel unfinished.

### 6) Preserve what is already working
Do not redesign the whole page.
Preserve:
- v15 visual direction and branding;
- real project photos;
- service area map;
- Swiper carousel behavior;
- optimized image assets;
- SEO/title/meta/schema direction;
- no em dashes in visible user-facing copy;
- no promotion of waterproofing, concrete repair, drywall, or fences as current services.

## Deliverables
1. `/home/black/covered-on-prospects/tony-stucco/mockup-report/tony-stucco-client-share-mockups-v16.html`
2. Updated `/home/black/covered-on-prospects/tony-stucco/mockup-report/README.md` with v16 notes and verification.
3. New desktop and mobile screenshots if practical.
4. Completion summary with exact copy/link/layout changes.

## Verification requirements
Before requesting review or marking done:
- Confirm v16 file exists and v15 is preserved.
- Serve/render v16 locally.
- Check browser console errors/warnings.
- Verify desktop render.
- Verify mobile render at 390px and 375px.
- Verify `document.documentElement.scrollWidth <= window.innerWidth + 1` on mobile.
- Verify carousel cycles through all slides and all major images load with natural dimensions.
- Verify map image loads with nonzero dimensions.
- Verify no primary CTA remains `href="#"`.
- Verify all phone links use valid `tel:+12393508845` format or another confirmed valid number.
- Verify no em dashes in visible user-facing copy.
- Verify outdated services are not promoted: waterproofing, concrete repair, drywall, fences.
- Verify the stale property-manager/general-contractor language is removed or reframed.

## Review
After implementation, request independent review. The reviewer should verify the file, browser behavior, mobile overflow, CTA links, copy cleanup, and screenshots before the card is considered complete.

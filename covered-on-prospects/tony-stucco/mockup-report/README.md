# Tony Stucco Service LLC — Website Direction Report

## What was created

A single-file HTML report for Covered On's internal review before sharing with Tony Stucco Service LLC. The report contains:

- **Cover/intro** with charcoal header
- **Intake summary** from the Covered On onboarding conversation
- **Website goals** — what the site should accomplish for Tony's business
- **Brand positioning and direction** — anchored in stucco/material tones with controlled green/gold accents
- **11 follow-up questions** for Tony to answer before finalizing the site
- **Three embedded homepage mockup directions** (above-the-fold previews in browser frames):
  - A: Clean Local Contractor (warm/sand/olive, residential trust)
  - B: Pro Builder Partner (charcoal/gold, contractor confidence)
  - C: Bright Accent Concept (neutral base with green/gold accents — **recommended**)
- **Comparison table** with recommendation for Direction C
- **Next steps** — 7-step plan from direction selection through launch

## Client-Share Version

### v1

`tony-stucco-client-share-mockups.html` — client-facing version for sharing with Tony Stucco Service LLC. Key changes from the internal report:

- Removed internal strategy/report language; rewrote for direct contractor audience
- Stripped AI/marketing fluff (warm, inviting, brand essence, visual direction, etc.)
- Rephrased follow-up questions as plain, practical asks
- Removed SEO overpromises and internal positioning language
- Added `noindex, nofollow` meta tag for safe hidden-link sharing
- Added contact confirmation note (phone/email should be verified before launch)
- Renamed sections: "What We Know So Far", "Color and Style Approach", "What We Need From You", "Homepage Options"
- No em dashes in body copy
- Mockups and comparison table preserved unchanged

### v2 (Photo-Heavy Revision)

`tony-stucco-client-share-mockups-v2.html` — revised with project photo emphasis, inspired by Orlando competitor analysis (United Painting, Orlando Stucco Contractors, Reid's Stucco, EmpireWorks).

Changes from v1:
- All 3 homepage mockups redesigned to be photo-led with 10 CSS photo placeholders
- Option 1: Split hero (text + 2-photo stack), 3-photo service strip below hero
- Option 2: Large hero project image, 4 scope chips, featured project case-study card with photo + scope bullets
- Option 3: Hero image placeholder, before/after pair, photo gallery CTA
- Client-facing note about placeholder images near mockups
- Section 2 updated to emphasize project photos as site goal #1
- Section 3 added "Photo-Heavy Design Approach" subsection
- Section 4 restructured: project photos moved to top priority with 6 specific photo types requested
- Section 6 comparison table: added "Photo approach" and "Image emphasis" rows
- Section 7 step 2 rewritten to prioritize photo submission
- No em dashes, no fluffy terms, noindex/nofollow preserved

### v9 (Intro-First Hero + Contrast Improvements)

`tony-stucco-client-share-mockups-v9.html` -- restructured hero layout so the intro/company/service text comes before the image carousel, plus contrast fixes. Key changes from v8:

**Layout restructuring:**
- Hero section changed from two-column side-by-side grid (text right, carousel left) to a stacked layout where the intro text comes FIRST, then the full-width Swiper carousel beneath it
- Desktop: company label, headline, body copy, CTA, and audience labels appear above the carousel
- Mobile: same stacked order -- text block first, carousel second (confirmed via DOM order and full-page screenshot)
- Hero content constrained to 720px max-width for comfortable reading line length
- Hero-photo height set to 480px (desktop), 420px (<=900px), 360px (<=500px) -- matches v8 mobile fix heights

**Contrast improvements:**
- `--gray-text`: darkened from #555555 to #484848 for stronger body copy contrast against off-white backgrounds
- `--gray-muted`: darkened from #777777 to #5c5c5c for subdued labels
- `.hero-company-label`, `.section-label`, `.split-label`: changed from `var(--teal)` (#1BA3A3) to `var(--teal-dark)` (#148787) -- better contrast against cream/off-white backgrounds
- Inactive pagination dots: opacity bumped from 0.45 to 0.55 for better visibility on lighter image areas; hover state from 0.75 to 0.85
- Footer body/link text: opacity bumped from 0.6 to 0.7 against navy background

All v8 Swiper slider behavior, copy direction, Jacksonville-to-Tampa coverage language, residential exterior painting mentions, palette, and section content preserved intact.

- `tony-stucco-website-mockup-report.html` — internal direction report (985 lines, ~34KB)
- `tony-stucco-client-share-mockups.html` — client-share version v1 (~32KB)
- `tony-stucco-client-share-mockups-v2.html` — photo-heavy client-share revision v2 (~45KB). All 3 mockups redesigned to put project photos front and center: split hero with photo stack and service photo strip (Option 1), large project image with scope chips and featured project case-study card (Option 2), hero image with before/after pair and photo gallery CTA (Option 3). Updated Section 4 to prioritize project photos with specific photo types. Added client-facing photo placeholder note. Updated comparison table with photo approach and image emphasis rows.
- `tony-stucco-client-share-mockups-v3.html` — production homepage mockup v3 (~22KB). Single full-page design matching real-site reference. Green/yellow color scheme. Sections: banner, header, hero, services, warning signs, split CTA, footer. 0 em dashes, 0 fluffy terms.
- `tony-stucco-report-fullpage.png` — full-page screenshot for quick preview
- `tony-stucco-client-share-mockups-v4.html` — logo-driven v4 revision (~24KB). Teal/navy/orange palette pulled from approved logo. Real logo PNG used. All 5 supplied project photos used throughout: hero, 4-photo proof grid, featured project strip, and split CTA. New "Real Projects" section with masonry-grid proof cards. No placeholder graphics remain. Em dashes and banned terms verified absent.
- `tony-stucco-v4-fullpage.png` — full-page screenshot of v4 rendering
- `tony-stucco-client-share-mockups-v5.html` — carousel-enhanced v5 revision (~31KB). Hero image replaced with 5-slide swipeable carousel. All real project photos. Desktop click controls, mobile swipe support, dot indicators, keyboard accessible. Vanilla JS, zero dependencies.
- `tony-stucco-client-share-mockups-v6.html` -- hero carousel CSS hotfix v6 (~31KB). Fixed hero carousel height blowout by switching from relative+height:100% to absolute+inset:0. All v5 features preserved.
- `tony-stucco-client-share-mockups-v7.html` -- copy refresh v7 (~31KB). Clarified residential exterior painting service in hero, body, services, and footer. Updated coverage area from Orlando+30mi to Jacksonville-to-Tampa corridor. All v6 carousel/layout preserved.
- `tony-stucco-v5-fullpage.png`, `tony-stucco-v5-hero-carousel.png`, `tony-stucco-v5-mobile.png` -- v5 screenshots
- `tony-stucco-v6-hero-desktop.png`, `tony-stucco-v6-mobile.png`, `tony-stucco-v6-fullpage.png` -- v6 screenshots
- `tony-stucco-v7-hero-desktop.png`, `tony-stucco-v7-mobile.png`, `tony-stucco-v7-fullpage.png` -- v7 screenshots
- `tony-stucco-v8-fullpage.png`, `tony-stucco-v8-hero-desktop.png`, `tony-stucco-v8-mobile.png`, `tony-stucco-v8-mobile-fullpage.png` -- v8 screenshots
- `tony-stucco-v9-fullpage.png`, `tony-stucco-v9-hero-desktop.png`, `tony-stucco-v9-mobile.png`, `tony-stucco-v9-mobile-fullpage.png` -- v9 screenshots
- `tony-stucco-client-share-mockups-v9.html` — intro-first v9 revision (~32KB). Hero restructured: intro text now appears before the carousel (stacked instead of side-by-side). Contrast improved: darker gray body text (#484848), darker teal labels (#148787), brighter pagination dots (0.55 opacity), stronger footer text (0.7 opacity).

### v6 (Hero Carousel CSS Hotfix)

`tony-stucco-client-share-mockups-v6.html` — layout hotfix for the v5 hero carousel height blowout. Key change from v5:

- **Root cause:** `.hero-carousel` used `height: 100%` chain without a resolved parent height — `.hero-photo` had `min-height` but no explicit `height`, so the percentage resolved to `auto`, images used natural dimensions (~2992px), blowing the hero to ~5657px.
- **Fix:** Changed `.hero-carousel` from `position: relative; width: 100%; height: 100%` to `position: absolute; inset: 0`. Now the carousel fills the `.hero-photo` container which gets its height from the CSS Grid row (determined by `.hero-content`'s natural height + `min-height: 500px`).
- All v5 design, palette, carousel JS behavior, and mobile layout preserved.
- Desktop hero verified: carousel 600x533px (1280px viewport), images properly cropped with `object-fit: cover`, hero copy visible beside carousel.
- Mobile verified: carousel 375x280px (375px viewport), single-column stack clean.
- Carousel controls (next/prev, dots, keyboard arrows) confirmed functional.
- 0 em dashes, 0 banned fluffy terms, noindex/nofollow present.

### v3 (Real-Site Production Direction)

`tony-stucco-client-share-mockups-v3.html` — single production-style homepage mockup matching the real contractor website reference design shared by Reknown. Key changes from v2:

- Replaced 3-mockup concept approach with a single full-page production homepage
- Green/yellow color scheme: dark green headers, yellow badges and CTA buttons, white backgrounds
- Full multi-section layout: yellow service banner, sticky header with logo+nav, hero section with worker photo placeholder and 3 audience labels, numbered service sections (01-04), 4-column stucco warning signs grid, split-image CTA section, dark green footer
- Removed report framing, cover page, option comparison table, and "pick an option" guidance
- Copy matches reference tone: direct, contractor-facing, short declarative sentences, problem/solution framing for stucco damage
- Photo placeholders with descriptive labels (e.g., "Worker applying stucco finish to home exterior")
- Client-facing note explaining placeholder images
- noindex/nofollow preserved, no em dashes, no fluffy terms

### v4 (Logo-Driven Real Photo Refresh)

`tony-stucco-client-share-mockups-v4.html` — refreshed with Tony's approved logo and real project photos. Key changes from v3:

- Color palette pulled directly from approved logo: teal (#1BA3A3), deep navy (#1A2B4C), orange (#E87800), stucco cream
- Real logo PNG replaces CSS circle placeholder in header and footer
- All 5 project photos used: hero (new build corner), proof grid (chimney, wall close-up, house side, long wall), featured strip (chimney), split CTA (house side)
- New Section 03 "Real Projects" with 4-photo masonry grid and hover effects
- Section 04 combines warning signs with featured project photo strip
- Green/yellow palette fully removed; replaced by teal/navy/cream
- Service banner and badges now teal; CTAs teal or navy
- 0 placeholder graphics remain -- all images are real project photos or the approved logo
- noindex/nofollow, 0 em dashes, 0 fluffy terms verified

## Design decisions

- Colors anchored in stucco tones (warm white, sand, charcoal, olive) using Tony's submitted greens (#36420a, #567a1f) as controlled accents — not neon, not dominant
- Gold (#C49A2C) used for CTAs and highlights only
- Realistic placeholder copy throughout — no Lorem Ipsum
- No fake stats, testimonials, icon grids, testimonial carousels, or AI-website cliches
- No em dashes in user-facing copy
- Clean wordmark "Tony Stucco Service LLC" on all mockups (no logo yet)
- Report is printable and shareable in a single browser file

## Caveats

- The mockups are concept previews, not production website code
- Always test the report in browser before sending to the client — verify at common viewport widths
- The report references Tony's phone number and email — confirm with Covered On that these are approved for inclusion before external sharing
- Bright green/yellow usage in Direction C should be reviewed with Tony to confirm the accent level is right for him
- Missing info (reviews, photos, licensing wording) is called out in Section 4 — the final website quality depends on gathering these

## Verification Performed

### v1
- Tag balance: all HTML tags properly closed
- DOM structure: all 6 sections, 3 mockups, 2 callout boxes, 7 next steps confirmed present
- Browser render: tested in Chromium via Playwright; all mockup frames, tables, and sections render correctly
- No JavaScript errors (only favicon.ico 404, which is expected in local HTML)
- Color contrast: dark text on light backgrounds, white on charcoal — meets readability standards

### v2
- Browser render: tested in Chromium via Playwright; all 3 mockup frames, photo placeholders, before/after pair, scope chips, and case-study card render correctly
- Structural checks: 10 photo placeholders, 4 scope chips, 1 case-study card, 1 before/after pair, 1 photo strip, 1 photo stack, client-facing photo note present
- No JavaScript errors (only favicon.ico 404)
- noindex/nofollow meta tag present
- No em dashes in visible body copy
- No banned fluffy terms in visible body copy (warm, inviting, brand essence, visual direction, tone, polished business, homeowner-friendly)
- Photo emphasis terms confirmed: 38 total matches across project photo, before and after, stucco repair photo, exterior painting, concrete repair, and related terms

### v3
- Browser render: tested in Chromium via Playwright; all sections render correctly
- Section inventory: yellow service banner, sticky header with logo+nav+phone+CTA, hero section with photo placeholder and audience labels, 3 numbered content sections with yellow badges, 4-column warning signs grid, split-image CTA section, dark green footer
- No JavaScript errors (only favicon.ico 404)
- noindex/nofollow meta tag present
- 0 em dashes confirmed
- 0 banned fluffy terms confirmed (warm, inviting, brand essence, visual direction)
- 2 photo placeholders: hero worker photo, split CTA project photo

### v4
- Browser render: tested in Chromium via Playwright; all sections render correctly with real photos
- Logo: approved Tony Stucco logo PNG used in header and footer (2 instances)
- Real project photos: all 5 source-assets images used (7 total references across page)
- Section inventory: teal service banner, sticky header with real logo, hero with Project 5 photo, 2-col intro, numbered services list, 4-photo project proof grid, featured project strip with warning signs, split CTA with Project 3 photo, navy footer
- No JavaScript errors (only favicon.ico 404)
- noindex/nofollow meta tag present
- 0 em dashes confirmed (including code comments)
- 0 banned fluffy terms confirmed
- Full-page screenshot saved: tony-stucco-v4-fullpage.png (720K)

### v5 (Hero Carousel Enhancement)

`tony-stucco-client-share-mockups-v5.html` — added a swipeable project photo carousel to the hero section. Key changes from v4:

- Hero image area replaced with a 5-slide carousel using all real project photos
- Desktop: clickable prev/next arrow buttons (semi-transparent white circles, SVG chevrons)
- Mobile: touch/pointer swipe support with a 50px threshold
- Dot indicators at bottom of carousel for direct slide navigation
- Keyboard accessible: ArrowLeft/ArrowRight when carousel region is focused
- Smooth CSS transition (0.45s cubic-bezier) with prefers-reduced-motion support
- Zero external dependencies -- lightweight vanilla JS (~60 lines)
- All v4 brand direction, palette, and layout preserved intact
- Mockup note updated to mention carousel

Verification:
- All 5 project photos loading and displaying in carousel
- Next/Prev buttons advance and wrap (slide 5 to slide 1, slide 1 to slide 5)
- Dot indicators track current slide and support direct jump
- Mobile 375px viewport tested: carousel controls functional, single-column layout correct
- 0 console errors (only expected favicon.ico 404)
- 0 em dashes, 0 banned fluffy terms, noindex/nofollow present
- Screenshots saved: tony-stucco-v5-fullpage.png, tony-stucco-v5-hero-carousel.png, tony-stucco-v5-mobile.png

### v6 (Hero Carousel CSS Hotfix)

Verification:
- Desktop 1280x900 viewport: hero carousel resolves to 600x533px (fills grid column), images cropped with `object-fit: cover`, hero copy visible beside carousel in first viewport
- Mobile 375x812 viewport: carousel resolves to 375x280px, single-column stack clean, carousel at top, text below
- Carousel controls confirmed: Next/Prev buttons advance and wrap, dot indicators track current slide
- 1 console error (favicon.ico 404 — expected for local HTML)
- 0 em dashes, 0 banned fluffy terms, noindex/nofollow present
- Screenshots saved: tony-stucco-v6-hero-desktop.png, tony-stucco-v6-mobile.png, tony-stucco-v6-fullpage.png

### v7 (Residential Exterior Painting Copy + Coverage Area Update)

`tony-stucco-client-share-mockups-v7.html` -- copy refresh clarifying residential exterior painting service and updating coverage area from Orlando+30mi to Jacksonville-to-Tampa corridor. Key changes from v6:

**Residential exterior painting (7 visible mentions added):**
- Hero headline: "Stucco repair and residential exterior painting that holds up in Florida."
- Hero body: "Real stucco repair, residential exterior painting, waterproofing, and concrete work for homeowners and commercial clients..."
- Section 01 body: "...homeowner looking for residential exterior painting and stucco repair..." + "...full exterior refresh including exterior painting for homes..."
- Service list item 02 (Exterior painting): "Residential exterior painting with professional-grade paint, surface prep, and finish work"
- Footer brand paragraph: "Stucco repair, residential exterior painting, waterproofing, and concrete repair..."
- Meta/OG tags updated to include "residential exterior painting"

**Coverage area update (4 visible mentions changed):**
- Service banner: "SERVING COMMUNITIES FROM JACKSONVILLE TO TAMPA" (was: Orlando + 30 miles)
- Section 01 label: "FLORIDA STUCCO SERVICE" (was: Stucco Service in Orlando)
- Projects section: "from across central Florida" (was: from the Orlando area)
- Footer brand: "serving communities from Jacksonville to Tampa" (was: Orlando + 30 miles)
- Footer bottom line: "Serving communities from Jacksonville to Tampa" (was: Orlando)
- Split CTA alt text: "in central Florida" (was: in Orlando area)
- Meta/OG tags updated accordingly

All v6 carousel layout, palette, JS behavior, and responsive breakpoints preserved intact. 0 em dashes, 0 banned fluffy terms, 0 "30 miles" references, noindex/nofollow present.

Verification:
- Desktop rendering: hero carousel correct proportions, residential exterior painting copy visible in hero, service list, section body, and footer
- Mobile 375x812 viewport: single-column stack clean, carousel functional
- 7 instances of "residential exterior painting" in visible copy
- 4 instances of "Jacksonville to Tampa" in visible copy
- 0 remaining "30 miles" references
- 0 em dashes, 0 banned fluffy terms
- 1 console error (favicon.ico 404 -- expected)
- noindex/nofollow present
- Screenshots saved: tony-stucco-v7-hero-desktop.png, tony-stucco-v7-mobile.png, tony-stucco-v7-fullpage.png

### v8 (Swiper Slider Replacement + Mobile Image Framing Fix)

`tony-stucco-client-share-mockups-v8.html` -- replaced the hand-rolled v6/v7 carousel with Swiper (CDN) and fixed mobile image framing. Key changes from v7:

- **Slider library:** Replaced custom ~60-line vanilla JS carousel with Swiper 11 from jsdelivr CDN. Swiper provides native touch/swipe, keyboard nav, infinite loop, a11y labels, and dot pagination out of the box.
- **Mobile image framing fix:** Increased `.hero-photo` min-height at breakpoints: 300px → 420px at 900px, 280px → 360px at 500px. The extra vertical space lets `object-fit: cover` frame photos reasonably instead of cropping to an unusably narrow strip.
- **Nav button styling:** Swiper's default arrows overridden to match v7's look: 40px white circles, navy chevrons, semi-transparent on idle, opaque on hover/focus.
- **Pagination dots:** Swiper bullets styled to match v7: 8px white dots, active dot scales to 1.3x with solid white.
- **prefers-reduced-motion:** CSS override disables all transitions; Swiper's `speed` handles smooth animation normally.
- **Zero JS errors:** Only expected favicon.ico 404 in console.
- All v7 copy, palette, layout, project grids, service lists, and footer preserved intact.

Verification:
- Desktop 1280x900 viewport: two-column hero grid renders clean — slider on left, text + CTA on right. Nav arrows and dots visible and clickable.
- Mobile 375x812 viewport: single-column stack — slider at top, text below. Swipe works natively. Images no longer zoomed-in; framing looks intentional.
- 1 console error (favicon.ico 404 — expected)
- 0 em dashes, 0 banned fluffy terms, noindex/nofollow present
- Screenshots saved: tony-stucco-v8-fullpage.png, tony-stucco-v8-hero-desktop.png, tony-stucco-v8-mobile.png, tony-stucco-v8-mobile-fullpage.png

### v9 (Intro-First Hero + Contrast Improvements)

Verification:
- Desktop 1280x900 viewport: stacked hero confirmed -- intro text (company label, headline, body, CTA, audience row) appears above full-width carousel. Carousel controls and dots functional.
- Mobile 375x812 viewport: stacked order preserved -- text block first, 5-slide Swiper carousel below with navigation dots visible. Swipe and dot interaction functional.
- DOM order: hero-content precedes hero-photo (text before images in all viewports).
- 1 console error (favicon.ico 404 -- expected)
- 0 em dashes, 0 banned fluffy terms, noindex/nofollow present
- Contrast fixes verified: gray-text #484848 (was #555), gray-muted #5c5c5c (was #777), teal labels at #148787 (was #1BA3A3), pagination dots 0.55 opacity (was 0.45), footer text 0.7 opacity (was 0.6)
- Screenshots saved: tony-stucco-v9-fullpage.png, tony-stucco-v9-hero-desktop.png, tony-stucco-v9-mobile.png, tony-stucco-v9-mobile-fullpage.png

# Covered On Portal -- Design Direction Packet

**Project:** Covered On Portal Django MVP
**Author:** Designer (Gate: UI direction packet)
**Date:** 2026-08-17
**Source of truth:** `COVERED_ON_DESIGN_SYSTEM_SPEC.md`
**Supersedes:** Any prior Bootstrap-based or MLPS-branded portal CSS/HTML

---

## 1. Portal Brand Stance

The portal is not a marketing website. It is a utility -- a tool the client and admin use to get work done. It should feel like an extension of the Covered On service relationship, not a generic SaaS dashboard.

### Brand posture for the portal

| Attribute | Portal stance | How it shows up |
|---|---|---|
| Utility-first | The portal is a tool, not a brochure | Dense information layouts, minimal decorative elements, clear next-action buttons |
| Trustworthy | Clients see only what belongs to them | Clean role isolation, clear labeling, no placeholders or fake data |
| Calm | No alerts, badges, or animations without a real state change | Gold is decorative only; green for success; muted ink for everything else |
| Owned | It clearly belongs to Covered On | Navy header/footer, Fraunces on major titles, green-deep CTAs, canopy motif in empty states only |
| Practical | Every page answers: "What can I do here?" | Action-oriented headings, visible primary CTA per section, status badges that mean something |

### What the portal must never feel like

- A Bootstrap admin template (rows of gray cards, generic blue links, default table styling)
- An MLPS-branded tool (no purple/teal, no MLPS logo, no MLPS service names)
- A placeholder with "coming soon" dead ends
- A faceless enterprise intranet
- A generic start-up dashboard with analytics no one asked for

### Portal personality keywords

Calm. Clear. Secure. Owned. Task-oriented. Practical.

---

## 2. Information Architecture

### Role-based views

The portal has three distinct user roles for IA purposes. Each sees a different tree.

**Admin / Covered On operator:**

```
/                              -> Admin dashboard (overview of all clients, recent activity)
/clients/                      -> Client list
/clients/<id>/                 -> Single client detail + service assignments
/services/                     -> Service catalog (all Covered On services)
/services/<id>/                -> Service detail
/assignments/                  -> Assignment management (which client gets which service)
/reports/                      -> Report/document metadata list
/reports/<id>/                 -> Report detail
/admin/                        -> Django admin (gated by staff + Authentik group)
```

**Client / customer user:**

```
/                              -> Client dashboard (own services, recent activity)
/services/                     -> My assigned services
/services/<id>/                -> Service detail (only if assigned)
/reports/                      -> My reports/documents
/reports/<id>/                 -> Report detail (only if own)
```

**Unauthenticated visitor:**

```
/                              -> Redirect to OIDC login
/health/                       -> Health check (unauthenticated, returns JSON)
```

### Why this structure

- Dashboard is the default landing for both admin and client after login. It shows what needs attention.
- Services and reports are sibling top-level sections because they are the two main work areas.
- The admin sees an additional "clients" section because they manage people, not just data.
- Django admin is deliberately namespaced under `/admin/` and gated by staff check. It is not the primary admin interface.

### Navigation labels (portal, not website)

| Label | Route | Visible to |
|---|---|---|
| Dashboard | `/` | All authenticated |
| My Services | `/services/` | Client |
| Services | `/services/` | Admin |
| My Reports | `/reports/` | Client |
| Reports | `/reports/` | Admin |
| Clients | `/clients/` | Admin only |
| My Account | (Authentik-managed) | All authenticated |

---

## 3. Page Inventory

### Phase 4 scope (current build phase)

**Landing / auth redirect pages:**

| Page | URL | Purpose |
|---|---|---|
| Login redirect | `/` | Unauthenticated visitors are redirected to Authentik |
| Login callback | (OIDC flow) | Authentik redirects back; session established |

**Dashboard pages:**

| Page | URL | Purpose |
|---|---|---|
| Admin dashboard | `/` | Overview: total clients, services, recent assignments, quick actions |
| Client dashboard | `/` | Overview: my assigned services, recent report activity |

**Service pages:**

| Page | URL | Purpose |
|---|---|---|
| Service list (admin) | `/services/` | All Covered On services, CRUD |
| Service list (client) | `/services/` | Only assigned services, read-only detail |
| Service detail | `/services/<id>/` | Service info, status, related reports |

**Client management pages (admin only):**

| Page | URL | Purpose |
|---|---|---|
| Client list | `/clients/` | All client accounts |
| Client detail | `/clients/<id>/` | Client info, assigned services, notes |

**Report/document pages:**

| Page | URL | Purpose |
|---|---|---|
| Report list (admin) | `/reports/` | All report metadata |
| Report list (client) | `/reports/` | Own report metadata |
| Report detail | `/reports/<id>/` | Report info, download, status |

**System pages:**

| Page | URL | Purpose |
|---|---|---|
| Health check | `/health/` | Container-runtime verification (JSON) |
| 400 Bad Request | error handler | Custom error page |
| 403 Forbidden | error handler | Custom error page |
| 404 Not Found | error handler | Custom error page |
| 500 Server Error | error handler | Custom error page |

### Pages explicitly excluded from MVP

- User registration (Gate 0 decision 2.1)
- API endpoints / REST layer (Gate 0 decision 2.2)
- Password reset / account management (handled by Authentik externally)
- Service provider portal (future scope)
- Billing / subscription pages (requires Reknown approval per Gate 0)
- Public-facing portal pages that do not require auth

---

## 4. Layout Approach

### Portal grid

The portal uses a single-column layout with constrained max width for reading comfort. Not a freeform dashboard grid.

```
maxWidth: 1024px  (slightly narrower than the website's 1180px — portals are denser)
containerPaddingDesktop: 28px
containerPaddingMobile: 20px
```

### Section rhythm

```
sectionPaddingDesktop: 40px  (tighter than website — portal is work, not marketing)
sectionPaddingMobile: 32px
```

### Page composition pattern

Every portal page follows the same skeleton:

1. **Top bar** (navy, full width): Logo left, navigation right, user menu far right
2. **Page header** (white/paper): Title (Fraunces display-md), optional subtitle, optional breadcrumb
3. **Utility bar** (optional, below page header): Search, filter, action buttons
4. **Content area** (paper or paper-alt background): Cards, tables, forms, details
5. **Footer** (navy, minimal): Copyright, privacy link

### Page header subtypes

**Dashboard:**
- Large Fraunces title: "Good morning, [name]"
- Subtitle: "Here is what needs attention today."
- Stat cards in a 2-4 column row below the title

**List pages (services, clients, reports):**
- Fraunces title: "Services" / "Clients" / "Reports"
- Optional filter/search bar
- Card or table list below

**Detail pages:**
- Fraunces title: the entity name
- Breadcrumb: Dashboard > Services > Service Name
- Detail sections in stacked panels

### Layout rules

- Stack to single column below 720px.
- Two-column layouts only for: sidebar + main content, or form + preview panels.
- No complex dashboard grid layouts in MVP. Single column with readable cards.
- Keep whitespace generous but not wasteful. Portal pages should feel organized, not empty.
- Use hairline borders (`line` token) between sections, not heavy shadows.

---

## 5. Component Language

### 5.1 Buttons

**Primary action:**
- Background: `green-deep` (`#145240`)
- Text: `white` (`#ffffff`)
- Shape: `14px` radius in portal UI (pill shape is reserved for marketing pages)
- Padding: `12px 22px`
- Hover: `navy` (`#0a2740`)
- Font: Inter, 600 weight, `15px`
- Icon: Heroicon on the left or right; 18x18, white stroke

**Secondary / ghost action:**
- Background: transparent
- Border: `line` (`rgba(20, 36, 32, 0.12)`)
- Text: `navy` (`#0a2740`)
- Hover: gold border (`#c79a3e`)
- Font: Inter, 500 weight, `15px`

**Danger action (rare, real destructive actions only):**
- Background: `white`
- Border: `#b3402a` (audit fail/red)
- Text: `#b3402a`
- Hover: `#b3402a` background, white text

**Button rules:**
- One primary action per section. No competing primaries.
- Use ghost/secondary for table row actions, secondary navigation, cancel.
- No bounce, pulse, or continuous animation on buttons.
- Touch target minimum: 44px.

### 5.2 Cards and panels

**Standard portal card:**
```
backgroundColor: #ffffff
border: 1px solid rgba(20, 36, 32, 0.12)
borderRadius: 14px
padding: 20px
boxShadow: none (use borders, not shadows)
hover: subtle lift (2px translateY, soft shadow)
```

**Dashboard stat card:**
```
Same as standard card but:
- Optional gold top rule (2px, #c79a3e)
- Large stat number in Fraunces or Inter 700
- Small label below in ink-soft
```

**Detail panel (for report/service detail):**
```
backgroundColor: #ffffff
border: 1px solid rgba(20, 36, 32, 0.12)
borderRadius: 14px
padding: 24px
margin-bottom: 16px
```

**Navy panel (for featured/empty states):**
```
backgroundColor: #0a2740
textColor: #ffffff
borderRadius: 18px
padding: 36px
```

### 5.3 Navigation

**Top bar (persistent across all portal pages):**
```
backgroundColor: #0a2740 (navy)
height: 60px
Logo: covered-on-logo-whitebg.webp, 160px wide, vertically centered
Nav links: white text, Inter 500, 14px
Active nav link: gold underline or green-deep bottom border
User menu: white text, dropdown on click (name, logout)
```

**Mobile navigation:**
- Hamburger toggle at 720px and below
- Full-screen vertical overlay or slide-in drawer
- Navy background, white text
- Close button top-right

**Breadcrumbs:**
- Inter, 13px, ink-soft
- Separator: `/` in ink-soft
- No breadcrumbs on dashboard page

**Navigation rules:**
- Active page must have a visible active state (underline or tinted background)
- Focus states must be visible (2px navy or green outline)
- External links (if any) use `rel="noopener noreferrer"`
- No dropdowns in MVP navigation unless service count requires them

### 5.4 Forms

**Form field:**
```
Input background: #ffffff
Border: 1px solid rgba(20, 36, 32, 0.12)
BorderRadius: 10px
Padding: 10px 14px
Font: Inter, 15px, #142420
Focus: 2px solid #1f7a5c border, soft green box-shadow (rgba(31, 122, 92, 0.15))
Label: Inter, 14px, 600 weight, #142420, always visible above the input
Error state: 2px solid #b3402a border, error text in #b3402a below input
Helper text: Inter, 13px, #3d504a
```

**Form section panel:**
```
backgroundColor: #f3f6f4 (paper)
borderRadius: 18px
padding: 28px
margin-bottom: 20px
Section title: Inter, 16px, 700 weight, #0a2740
```

**Submit button:**
- Primary button style (green-deep)
- Copy must describe the action: "Save changes", "Create service", "Update assignment"
- Never use "Submit" alone -- describe the action

**Form rules:**
- Labels are always visible (no floating label pattern)
- Required fields marked with `*` in the label
- Inline validation on blur for critical fields
- Form-level error summary at the top for server errors
- No CAPTCHA in MVP (Authentik handles auth)

### 5.5 Tables

Tables are used for dense data lists (client list, assignment list, report list).

```
Header row: paper-alt background (#eaefec), Inter 13px 600, ink-soft text, uppercase
Body row: white background, Inter 14px 400, ink text
Row hover: subtle paper tint
Border: hairline rgba(20, 36, 32, 0.06) between rows
BorderRadius: 10px on the table container
Padding: 12px 16px per cell
```

**Table rules:**
- Responsive: stack to cards below 720px or use horizontal scroll
- Sortable columns use a click indicator (small chevron icon)
- Action column last (edit, view, delete icons or buttons)
- No grid lines every row -- use subtle row stripes or border-bottom only

### 5.6 Status badges

Badges communicate service assignment states, report statuses, and audit findings.

```
Badge shapes: pill (borderRadius: 999px)
Padding: 4px 12px
Font: Inter, 12px, 600 weight, uppercase
```

| State | Background | Text |
|---|---|---|
| Active / Complete | `#1f7a5c` (green) | `#ffffff` |
| Pending / In Progress | `#0f3d5c` (blue) | `#ffffff` |
| Needs Review / Warning | `#8a6a22` (gold-text) | `#ffffff` |
| Draft / New | `rgba(20,36,32,0.08)` (pale ink) | `#3d504a` (ink-soft) |
| Critical / Failed | `#b3402a` (red) | `#ffffff` |

**Badge rules:**
- Use status colors only when the state is real. No decorative badges.
- Do not invent popularity, urgency, or "most requested" badges without real data.
- Keep badge text short: 1-2 words.

### 5.7 Icons (Heroicons)

Use Tailwind Heroicons (outline style, 18x24px default) from https://heroicons.com/.

**Approved icon usage in portal:**
- Navigation items: icon + label
- Action buttons: icon + text
- Status badges: small icon before status text
- Empty states: large icon (48-64px) centered above message
- Table row actions: icon-only buttons with title attribute

**Icon rules:**
- Use outline style consistently throughout the portal
- Keep stroke width consistent (Heroicons outline default: 1.5px)
- Icon color inherits from text color unless placed on a brand-colored background
- On navy backgrounds: use white or gold-soft icons
- On green-deep buttons: use white icons
- On light backgrounds: use ink or navy icons
- Do not mix Heroicons with other icon sets
- Do not animate icons (spin, bounce, pulse)

### 5.8 Progress and loading states

- Use a simple linear progress bar for real operations (report generation, data load)
- Bar color: green-deep (`#145240`)
- Background track: `rgba(20, 36, 32, 0.08)`
- Height: 4px
- For HTMX requests: add `hx-indicator` with a small spinner overlay or the linear bar
- Do not use skeleton screens or shimmer animations in MVP

### 5.9 Empty states

Every list page needs an empty state when no data exists. Empty states are authored, not blank.

Pattern:
1. Large Heroicon (64px, ink-soft, centered)
2. Fraunces heading (display-md, center): "No services yet"
3. Inter body text (body-md, center): "Services will appear here once they are assigned to your account."
4. Optional CTA button (if the user can take action): "Get covered" or "Add your first service"
5. Optional canopy arc as a subtle background accent (one per empty state)

---

## 6. Interaction Stance

### Default interaction model: server-rendered + HTMX

All interactions are server-rendered Django template responses. HTMX handles dynamic updates (form submissions, list filters, inline edits) without full page reloads.

**Approved HTMX patterns:**
- `hx-post` for form submissions that update a section
- `hx-get` for filtering lists, loading detail panels
- `hx-trigger` with `debounce` for search-as-you-type
- `hx-target` for scoped updates (replace a card, not the whole page)
- `hx-swap` with `outerHTML` for list item replacement
- `hx-indicator` for loading states on slow operations
- `hx-confirm` for destructive actions (delete, remove)

**Disallowed interaction patterns:**
- Full page reload for a single item update (use HTMX)
- Custom JavaScript for what HTMX handles natively
- Client-side routing, SPA patterns, or pushState manipulation
- WebSockets or real-time push in MVP (polling via HTMX if needed later)

### Hover behavior

| Element | Behavior |
|---|---|
| Buttons | Background color shift (green-deep to navy) |
| Cards | 2px translateY lift, soft shadow |
| Table rows | Subtle paper tint on background |
| Navigation links | Gold underline on current page, subtle tint on hover |
| Action icons | Color change or background circle |

### Focus behavior

- All interactive elements must have visible focus states
- Focus ring: 2px solid `#1f7a5c` (green) with 2px offset
- Do not use `outline: none` without providing a visible alternative
- Skip links to main content at top of page

### Click behavior

- Primary buttons: immediate server action via HTMX or standard form post
- Table row clicks: navigate to detail page (entire row is clickable)
- Card clicks: navigate to detail page (entire card is clickable)
- No double-click protection needed for MVP (HTMX prevents duplicate submissions naturally)

### Reduced motion

All interactions must respect `prefers-reduced-motion: reduce`:
- No smooth scroll
- No entrance animations
- No hover lift transitions
- No card entrance fades
- Keep loading indicators as static visual elements, not animated

---

## 7. Anti-Patterns

### What must NOT appear in the Covered On Portal

**Visual anti-patterns:**
1. Bootstrap default styling -- blue links, gray cards, default table borders, striped rows with Bootstrap blue
2. Bright generic gradients as section backgrounds
3. Stock icon grids that look like a generic SaaS dashboard
4. Purple, teal, orange, or bright blue -- those are not Covered On colors
5. Heavy box shadows on cards or panels
6. Random accent colors not in the brand palette
7. AI-style rainbow or neon gradients
8. Floating decorative elements (icons, dashes, dots without purpose)
9. Carousels, sliders, or auto-rotating content in a portal context
10. Fake data, placeholder avatars, or Lorem Ipsum in client-facing pages

**Copy anti-patterns:**
1. MLPS name, brand, address, phone number, or email anywhere in the portal
2. "Coming soon" labels on features that are not actively being built next
3. Fake testimonials, customer counts, or satisfaction percentages
4. Hype language: "revolutionize", "game-changing", "supercharge", "dominate"
5. Em dash (--), en dash (-), or ellipsis (...) characters -- use standard hyphens, commas, and periods
6. "Powered by AI", "AI-powered", or similar claims unless operationally true and specific
7. Percentage guarantees or outcome promises
8. Urgency language that is not real

**Interaction anti-patterns:**
1. Parallax scrolling, scroll-jacking, or infinite scroll on portal pages
2. Auto-playing video or audio
3. Push notifications, modal pop-ups on page load
4. Confetti, celebration animations, or gamification elements
5. Drag-and-drop without server-side confirmation
6. Gesture conflicts with browser navigation (swipe back/forward)
7. Form submissions that do not show loading or confirmation state
8. Dead links or actions that say "click here" but go nowhere

---

## 8. Corrections and Resolved Conflicts

### Conflict: Earlier Bootstrap assumptions (Gate 0 default)

The Gate 0 Principal Reviewer defaulted to "Bootstrap 5 via CDN" as an MVP CSS approach. This design direction **overrides** that default. The portal uses:

- Hand-written CSS following the Covered On design system tokens (Fraunces + Inter, brand palette, custom components) -- **not** Bootstrap
- Tailwind CSS is noted as a possible future iteration but is not introduced in Phase 4
- Heroicons from https://heroicons.com/ are the icon set
- No Bootstrap grid, components, or utility classes

Rationale: Bootstrap's default styling conflicts with the Covered On brand at every level -- typography, color, spacing, radius, component language. Stripping Bootstrap defaults to re-theme it would produce more CSS overrides than writing brand-native CSS directly.

### Conflict: MLPS brand references

The earlier portal work (FastAPI version at `v12`/`v13` in this repo's history) contained MLPS-branded colors, copy, and assumptions. This design direction **explicitly rejects** all MLPS references:

- Zero MLPS copy, colors, language, addresses, phone numbers, or assumptions
- Portal login and all pages use "Covered On" exclusively
- The brand navy/green/gold/paper palette replaces any prior MLPS teal/purple

### Conflict: Existing portal CSS in `covered/static/covered/css/site.css`

The existing `site.css` uses:
- System font stack instead of Fraunces + Inter
- `#1A1A1A` text color instead of `#142420` (ink)
- `#D6DED6` border color instead of `rgba(20, 36, 32, 0.12)` (line)
- `6px` border radius instead of 10px/14px/18px
- `#E8F5E9` / `#2E7D32` green instead of `#1f7a5c` / `#145240`

This CSS must be rewritten to match the design system spec before any portal page is deployed. The existing stylesheet is a starting skeleton that was never brand-fitted.

### Conflict: Gold link color in existing CSS

The current `site.css` sets `color: #c79a3e` for links. Gold is decorative, not a readable link color on light backgrounds. The design system specifies `gold-text` (`#8a6a22`) for readable gold on light surfaces. Links should use `blue` (`#0f3d5c`) per the color token spec.

### Pagination and list UX

For list pages (services, clients, reports with 20+ items), use traditional page-numbered pagination rather than infinite scroll. Page size default: 20 items.

---

## 9. Accessibility Baseline

The portal targets WCAG AA minimum. Critical items for Phase 4 implementation:

- All form inputs have associated `<label>` elements (never placeholder-as-label)
- Color contrast: body text on paper/white meets 4.5:1 ratio
- Touch targets: minimum 44px for all interactive elements
- Focus states: visible on all interactive elements (2px green outline)
- Heading hierarchy: h1 > h2 > h3, no skipped levels
- Alt text on all images and icons that convey meaning
- Decorative icons use `aria-hidden="true"`
- Skip link to main content at the top of every page
- `prefers-reduced-motion` respected for all animations and transitions
- Error messages are associated with their form fields via `aria-describedby`

---

## 10. Implementation Priority for Phase 4

| Priority | Item | Notes |
|---|---|---|
| P0 | Rewrite site.css to Covered On brand tokens | Blocks every visual deliverable |
| P0 | Update base.html template with Fraunces + Inter fonts | Google Fonts or self-hosted |
| P0 | Create navy top-bar navigation with logo | Shared across all pages |
| P0 | Create navy footer | Minimal, shared across all pages |
| P1 | Admin dashboard page | Stat cards, recent activity list |
| P1 | Client dashboard page | My services, recent reports |
| P1 | Service list + detail pages | Role-filtered, cards with status badges |
| P1 | Client list + detail pages (admin) | Table layout, responsive |
| P1 | Report list + detail pages | Status badges, download action |
| P1 | Empty states for all list pages | Authored messages, canopy accent |
| P2 | HTMX integration for filters and inline updates | List filtering, form submission |
| P2 | Error pages (400/403/404/500) branded | Currently minimal HTML |
| P2 | Responsive navigation (hamburger at 720px) | Slide-in drawer, navy |
| P3 | Search/filter on list pages | HTMX-driven |
| P3 | Pagination component | Page-numbered |
| P3 | Dark mode (future consideration) | Not in scope for Phase 4 |
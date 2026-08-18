# Covered On Portal -- UI Implementation Brief

**Target:** Web-dev worker implementing Phase 4 UI
**Source of truth:** `COVERED_ON_DESIGN_SYSTEM_SPEC.md` at `/home/black/covered_on_website/COVERED_ON_DESIGN_SYSTEM_SPEC.md`
**Design direction:** `DESIGN_DIRECTION_PACKET.md` (this repo)
**Supersedes:** Any prior Bootstrap assumptions, MLPS colors/copy, or existing `site.css` styles
**Stack:** Django templates, hand-written CSS (no Bootstrap, no Tailwind for Phase 4), HTMX, vanilla JS, Heroicons

---

## 1. Design Tokens (Copy-Paste Ready)

These are the exact CSS custom properties to define at `:root` in `covered/static/covered/css/site.css`. Every token below comes from the Covered On design system spec.

### Color tokens

```css
:root {
  /* Brand palette */
  --color-navy: #0a2740;
  --color-blue: #0f3d5c;
  --color-green: #1f7a5c;
  --color-green-deep: #145240;
  --color-gold: #c79a3e;
  --color-gold-soft: #e6c877;
  --color-gold-text: #8a6a22;
  --color-paper: #f3f6f4;
  --color-paper-alt: #eaefec;
  --color-white: #ffffff;
  --color-ink: #142420;
  --color-ink-soft: #3d504a;
  --color-line: rgba(20, 36, 32, 0.12);
  --color-line-weak: rgba(20, 36, 32, 0.06);
  --color-red: #b3402a;
}
```

### Typography tokens

```css
:root {
  --font-display: "Fraunces", "Iowan Old Style", Georgia, serif;
  --font-body: "Inter", -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;

  /* Fraunces sizes — clamped for responsive */
  --text-display-xl: clamp(2.4rem, 4.4vw, 3.6rem);    /* Hero-level headers */
  --text-display-lg: clamp(1.9rem, 4vw, 3.05rem);      /* Section headers */
  --text-display-md: clamp(1.5rem, 2.8vw, 1.875rem);   /* Page titles */

  /* Inter sizes */
  --text-heading-sm: clamp(1rem, 1.6vw, 1.125rem);     /* Card titles, form section titles */
  --text-body-lg: 1.0625rem;                            /* Lead text */
  --text-body-md: 1rem;                                 /* Main body copy */
  --text-body-sm: 0.875rem;                             /* Captions, helper */
  --text-eyebrow: 0.75rem;                              /* Section labels, uppercase */

  /* Font weights */
  --fw-regular: 400;
  --fw-medium: 500;
  --fw-semibold: 600;
  --fw-bold: 700;

  /* Line heights */
  --lh-tight: 1.1;     /* Fraunces display */
  --lh-body: 1.55;     /* Inter body */
  --lh-compact: 1.35;  /* Dense UI */

  /* Letter spacing */
  --ls-display: -0.01em;
  --ls-eyebrow: 0.14em;
}
```

### Layout tokens

```css
:root {
  --layout-max-width: 1024px;              /* Portal max width */
  --layout-content-width: 720px;           /* Reading width for forms/detail */
  --layout-padding-desktop: 28px;          /* Side padding on desktop */
  --layout-padding-mobile: 20px;           /* Side padding on mobile */
  --layout-section-desktop: 40px;          /* Vertical section padding */
  --layout-section-mobile: 32px;           /* Vertical section padding mobile */
  --layout-header-height: 60px;            /* Navy top bar */
}
```

### Spacing scale

```css
:root {
  --space-xs: 4px;
  --space-sm: 8px;
  --space-md: 16px;
  --space-lg: 24px;
  --space-xl: 32px;
  --space-xxl: 48px;
  --space-section: 40px;                  /* Portal section gap */
}
```

### Border radius

```css
:root {
  --radius-sm: 10px;          /* Form inputs, tables */
  --radius-md: 14px;          /* Cards, panels */
  --radius-lg: 18px;          /* Navy panels, form sections */
  --radius-pill: 999px;       /* Badges */
}
```

### Shadows

```css
:root {
  --shadow-card: 0 1px 3px rgba(20, 36, 32, 0.08);
  --shadow-card-hover: 0 4px 12px rgba(20, 36, 32, 0.12);
  --shadow-focus: 0 0 0 2px rgba(31, 122, 92, 0.25);
}
```

### Transitions

```css
:root {
  --transition-fast: 150ms ease;
  --transition-normal: 250ms ease;
}
```

---

## 2. Google Fonts Import

Add to `<head>` in `templates/base.html`:

```html
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Fraunces:opsz,wght@9..144,500;9..144,600;9..144,700&family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
```

---

## 3. Heroicons Integration

Load Heroicons via SVG sprite or inline SVGs. Do not use an NPM build step for Phase 4.

**Approach:** Download individual outline icons from https://heroicons.com/ and store as inline SVG partials in a Django template include, or reference them via a static SVG sprite.

**Recommended pattern for Django templates:**

```html
<svg class="icon" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="1.5" viewBox="0 0 24 24">
  <path stroke-linecap="round" stroke-linejoin="round" d="..." />
</svg>
```

**Icon sizes in portal:**

| Context | Size |
|---|---|
| Navigation items | 20x20 |
| Action buttons (with text) | 18x18 |
| Icon-only buttons | 20x20 |
| Empty state hero | 48x64 |
| Status badges | 14x14 |

---

## 4. Template Structure

### base.html (project-level)

```
templates/base.html
```

Skeleton:

```html
<!DOCTYPE html>
{% load static %}
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="description" content="Covered On Portal - Client service management">
  <meta name="color-scheme" content="light only">
  <title>{% block title %}Covered On Portal{% endblock %}</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="..." rel="stylesheet">
  <link rel="stylesheet" href="{% static 'covered/css/site.css' %}">
  {% block extra_head %}{% endblock %}
</head>
<body>
  {% block body %}
    {% include "covered/partials/skip_link.html" %}
    {% include "covered/partials/topbar.html" %}
    <div class="page-wrapper">
      {% block page_header %}{% endblock %}
      <main class="main-content" id="main-content" role="main">
        {% block content %}{% endblock %}
      </main>
    </div>
    {% include "covered/partials/footer.html" %}
  {% endblock %}
  <script src="{% static 'covered/js/app.js' %}"></script>
  {% block extra_scripts %}{% endblock %}
</body>
</html>
```

### Page template pattern

Each page follows:

```
{% extends "base.html" %}
{% block title %}Services — Covered On Portal{% endblock %}
{% block page_header %}
  {% include "covered/partials/page_header.html" with title="Services" %}
{% endblock %}
{% block content %}
  ... page content ...
{% endblock %}
```

---

## 5. Component CSS Classes

### Buttons

```css
.btn { font-family: var(--font-body); font-weight: var(--fw-semibold); font-size: var(--text-body-md); border-radius: var(--radius-sm); padding: 12px 22px; display: inline-flex; align-items: center; gap: var(--space-sm); cursor: pointer; transition: background var(--transition-fast), color var(--transition-fast); min-height: 44px; border: 1px solid transparent; text-decoration: none; line-height: 1; }
.btn-primary { background: var(--color-green-deep); color: var(--color-white); }
.btn-primary:hover { background: var(--color-navy); }
.btn-secondary { background: transparent; color: var(--color-navy); border-color: var(--color-line); }
.btn-secondary:hover { border-color: var(--color-gold); }
.btn-danger { background: transparent; color: var(--color-red); border-color: var(--color-red); }
.btn-danger:hover { background: var(--color-red); color: var(--color-white); }
.btn-ghost { background: transparent; color: var(--color-ink-soft); border: none; padding: 8px 12px; }
.btn-ghost:hover { color: var(--color-navy); background: var(--color-paper-alt); }
```

### Cards

```css
.card { background: var(--color-white); border: 1px solid var(--color-line); border-radius: var(--radius-md); padding: var(--space-lg); transition: box-shadow var(--transition-normal), transform var(--transition-normal); }
.card:hover { box-shadow: var(--shadow-card-hover); transform: translateY(-2px); }
.card--stat { padding: var(--space-xl); }
.card--stat .stat-value { font-family: var(--font-display); font-weight: var(--fw-semibold); font-size: var(--text-display-md); color: var(--color-navy); }
.card--stat .stat-label { font-size: var(--text-body-sm); color: var(--color-ink-soft); }
.card--accent { border-top: 2px solid var(--color-gold); }
.card--navy { background: var(--color-navy); color: var(--color-white); border: none; border-radius: var(--radius-lg); }
```

### Top bar

```css
.topbar { background: var(--color-navy); height: var(--layout-header-height); display: flex; align-items: center; justify-content: space-between; padding: 0 var(--layout-padding-desktop); position: sticky; top: 0; z-index: 100; }
.topbar__logo { height: 36px; width: auto; }
.topbar__nav { display: flex; align-items: center; gap: var(--space-md); }
.topbar__nav a { color: var(--color-white); font-family: var(--font-body); font-size: var(--text-body-sm); font-weight: var(--fw-medium); text-decoration: none; padding: 8px 12px; border-radius: var(--radius-sm); transition: background var(--transition-fast); }
.topbar__nav a:hover { background: rgba(255,255,255,0.1); }
.topbar__nav a.active { border-bottom: 2px solid var(--color-gold); }
.topbar__user { color: var(--color-white); display: flex; align-items: center; gap: var(--space-sm); cursor: pointer; }
```

### Tables

```css
.table-wrap { overflow-x: auto; border: 1px solid var(--color-line); border-radius: var(--radius-sm); }
table { width: 100%; border-collapse: collapse; }
thead th { background: var(--color-paper-alt); font-size: var(--text-eyebrow); font-weight: var(--fw-semibold); text-transform: uppercase; letter-spacing: var(--ls-eyebrow); color: var(--color-ink-soft); padding: 12px 16px; text-align: left; white-space: nowrap; }
tbody td { padding: 12px 16px; border-bottom: 1px solid var(--color-line-weak); font-size: var(--text-body-md); }
tbody tr:last-child td { border-bottom: none; }
tbody tr:hover { background: var(--color-paper); }
```

### Badges

```css
.badge { display: inline-flex; align-items: center; gap: 4px; padding: 4px 12px; border-radius: var(--radius-pill); font-size: 0.75rem; font-weight: var(--fw-semibold); text-transform: uppercase; letter-spacing: 0.04em; }
.badge--active, .badge--complete { background: var(--color-green); color: var(--color-white); }
.badge--pending, .badge--in-progress { background: var(--color-blue); color: var(--color-white); }
.badge--needs-review, .badge--warning { background: var(--color-gold-text); color: var(--color-white); }
.badge--draft, .badge--new { background: var(--color-paper-alt); color: var(--color-ink-soft); }
.badge--critical, .badge--failed { background: var(--color-red); color: var(--color-white); }
```

### Forms

```css
.form-group { margin-bottom: var(--space-lg); }
.form-label { display: block; font-size: var(--text-body-sm); font-weight: var(--fw-semibold); color: var(--color-ink); margin-bottom: var(--space-xs); }
.form-label .required { color: var(--color-red); margin-left: 2px; }
.form-input { width: 100%; padding: 10px 14px; font-family: var(--font-body); font-size: var(--text-body-md); color: var(--color-ink); background: var(--color-white); border: 1px solid var(--color-line); border-radius: var(--radius-sm); transition: border-color var(--transition-fast), box-shadow var(--transition-fast); }
.form-input:focus { outline: none; border-color: var(--color-green); box-shadow: var(--shadow-focus); }
.form-input--error { border-color: var(--color-red); }
.form-error { font-size: var(--text-body-sm); color: var(--color-red); margin-top: var(--space-xs); }
.form-helper { font-size: var(--text-body-sm); color: var(--color-ink-soft); margin-top: var(--space-xs); }
.form-section { background: var(--color-paper); border-radius: var(--radius-lg); padding: 28px; margin-bottom: var(--space-lg); }
.form-section__title { font-size: var(--text-heading-sm); font-weight: var(--fw-bold); color: var(--color-navy); margin-bottom: var(--space-md); }
```

### Empty states

```css
.empty-state { display: flex; flex-direction: column; align-items: center; text-align: center; padding: var(--space-xxl) var(--space-lg); }
.empty-state__icon { color: var(--color-ink-soft); margin-bottom: var(--space-md); }
.empty-state__title { font-family: var(--font-display); font-weight: var(--fw-semibold); font-size: var(--text-display-md); color: var(--color-navy); margin-bottom: var(--space-sm); }
.empty-state__text { font-size: var(--text-body-md); color: var(--color-ink-soft); max-width: 420px; margin-bottom: var(--space-lg); }
```

### Page header

```css
.page-header { padding: var(--space-xl) 0 var(--space-lg); }
.page-header__title { font-family: var(--font-display); font-weight: var(--fw-semibold); font-size: var(--text-display-md); color: var(--color-navy); margin: 0; }
.page-header__subtitle { font-size: var(--text-body-md); color: var(--color-ink-soft); margin-top: var(--space-xs); }
.breadcrumb { display: flex; align-items: center; gap: var(--space-sm); font-size: var(--text-body-sm); color: var(--color-ink-soft); margin-bottom: var(--space-sm); }
.breadcrumb a { color: var(--color-blue); text-decoration: none; }
.breadcrumb a:hover { text-decoration: underline; }
.breadcrumb__sep { color: var(--color-ink-soft); }
```

### Utility bar (search + filter)

```css
.utility-bar { display: flex; align-items: center; gap: var(--space-md); padding-bottom: var(--space-lg); flex-wrap: wrap; }
.utility-bar .search-input { flex: 1; min-width: 200px; max-width: 360px; }
```

---

## 6. Layout Structure (CSS)

### Page wrapper

```css
.page-wrapper { max-width: var(--layout-max-width); margin: 0 auto; padding: 0 var(--layout-padding-desktop); }

@media (max-width: 720px) {
  .page-wrapper { padding: 0 var(--layout-padding-mobile); }
}
```

### Section grid for dashboard stat cards

```css
.stat-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: var(--space-md); margin-bottom: var(--space-section); }
```

### Card grid for service/report lists

```css
.card-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: var(--space-md); }

@media (max-width: 640px) {
  .card-grid { grid-template-columns: 1fr; }
}
```

---

## 7. HTMX Integration Patterns

Add the HTMX script in `templates/base.html`:

```html
<script src="https://unpkg.com/htmx.org@2.0.4" integrity="sha384-..." crossorigin="anonymous"></script>
```

### Approved HTMX patterns for Phase 4

**List filtering (services, clients, reports):**

```html
<input type="text" name="q" class="form-input search-input"
       hx-get="{% url 'covered:service_list' %}"
       hx-trigger="keyup changed delay:300ms"
       hx-target="#service-list"
       hx-swap="outerHTML"
       placeholder="Search services...">
<div id="service-list">
  {% include 'covered/partials/service_list_items.html' %}
</div>
```

**Form submission (create/update):**

```html
<form hx-post="{% url 'covered:service_create' %}"
      hx-target="#service-list"
      hx-swap="beforebegin"
      hx-on::after-request="this.reset()">
  ...
  <button type="submit" class="btn btn-primary">Create service</button>
</form>
```

**Delete confirmation:**

```html
<button class="btn btn-danger btn-sm"
        hx-delete="{% url 'covered:service_delete' service.id %}"
        hx-confirm="Remove this service from all client assignments?"
        hx-target="#service-{{ service.id }}"
        hx-swap="outerHTML swap:1s">
  Delete
</button>
```

### HTMX conventions

- All HTMX endpoints return HTML fragments, not JSON
- Loading indicator uses `hx-indicator="#loading"` targeting a small element, not a full-page spinner
- Error responses return HTTP 422 or 400 with an HTML error fragment that the swap targets
- Use `hx-headers='{"X-CSRFToken": "{{ csrf_token }}"}'` on non-GET forms

---

## 8. Responsive Breakpoints

| Breakpoint | Behavior |
|---|---|
| > 1024px | Desktop: max-width container, multi-column grids, full top-bar |
| 721px - 1024px | Tablet: same layout, slightly tighter padding |
| ≤ 720px | Mobile: hamburger nav, single-column grids, horizontal scroll on tables |
| ≤ 480px | Small mobile: tighter padding, stacked stat cards, smaller headings |

### Mobile navigation

- Hamburger icon appears at ≤ 720px
- Click toggles a slide-in drawer from the left
- Drawer: navy background, white text, close button (X) top right
- Navigation links become vertical list with larger touch targets (48px+)
- Logo remains visible in the top bar when drawer is open
- Close drawer by: clicking X, clicking a nav link, tapping the overlay, pressing Escape

---

## 9. Accessibility Requirements

| Requirement | Implementation |
|---|---|
| Skip link | First focusable element on the page, visible on focus: "Skip to main content" |
| Heading hierarchy | h1 on every page (page title), h2 for card groups, h3 for card titles |
| Form labels | Every `<input>`, `<select>`, `<textarea>` has a `<label>` with `for` attribute |
| Error association | Error messages use `aria-describedby` pointing to the input's `id` |
| Focus outline | Never `outline: none` without `:focus-visible` alternative (use the green focus ring) |
| Touch targets | Minimum 44x44px for all interactive elements |
| Reduced motion | Wrap all transitions/animations in `@media (prefers-reduced-motion: no-preference)` |
| Alt text | Every `<img>` has descriptive alt text. Decorative SVGs have `aria-hidden="true"` |
| Color contrast | Body text (#142420 on #ffffff): 13.6:1. Footer text (white on #0a2740): 8.1:1. All pass AA. |
| Keyboard nav | Tab order follows visual order. Interactive elements receive focus. |

### Reduced motion media query template

```css
@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after {
    animation-duration: 0.01ms !important;
    animation-iteration-count: 1 !important;
    transition-duration: 0.01ms !important;
    scroll-behavior: auto !important;
  }
}
```

---

## 10. Files to Modify or Create

### Files to modify

| File | What to change |
|---|---|
| `covered/static/covered/css/site.css` | Complete rewrite with all tokens from Section 1 above |
| `templates/base.html` | Add Google Fonts link, HTMX script, Django static JS file, restructure per Section 4 |
| `covered/templates/covered/index.html` | Rewrite as the dashboard (admin or client based on auth) instead of a placeholder |

### Files to create

| File | Purpose |
|---|---|
| `covered/static/covered/js/app.js` | Vanilla JS: mobile nav toggle, dropdowns, focus management, reduced motion check |
| `templates/covered/partials/topbar.html` | Navy top bar with logo, nav links, user menu |
| `templates/covered/partials/footer.html` | Navy footer with copyright, privacy link |
| `templates/covered/partials/skip_link.html` | Skip to main content link |
| `templates/covered/partials/page_header.html` | Reusable page header (title, subtitle, breadcrumb) |
| `templates/covered/partials/badge.html` | Reusable status badge partial |
| `templates/covered/partials/empty_state.html` | Reusable empty state with icon, title, text, optional CTA |

### Files to create (page templates)

| File | Purpose |
|---|---|
| `covered/templates/covered/dashboard_admin.html` | Admin dashboard: stat cards, recent clients, recent reports |
| `covered/templates/covered/dashboard_client.html` | Client dashboard: my services, recent reports |
| `covered/templates/covered/service_list.html` | Service list with search/filter, card grid |
| `covered/templates/covered/service_detail.html` | Single service detail panel |
| `covered/templates/covered/client_list.html` | Admin client list with search, table |
| `covered/templates/covered/client_detail.html` | Admin client detail: info, assigned services |
| `covered/templates/covered/report_list.html` | Report list with status badges, download |
| `covered/templates/covered/report_detail.html` | Report detail with metadata |

---

## 11. Copy Guardrails

- Use "Covered On Portal" as the site title, not "Covered On" alone (reserve that for the marketing site)
- Use "My Services" for client-side service lists; use "Services" for admin
- Use "Log in" and "Log out" (not "Sign in" / "Sign out") for auth actions
- Use "Dashboard" for the home page nav label
- Do not use "Welcome back" or personal greeting unless the user's name is available from Authentik claims
- Status badge copy must match the backend's actual status values exactly
- No MLPS copy, brand name, address, phone number, or email -- anywhere
- No placeholder text, "coming soon", or Lorem Ipsum on any client-facing page
- No em dash, en dash, or ellipsis characters in any copy

---

## 12. Non-Negotiable Guardrails

1. **No Bootstrap.** The Gate 0 Bootstrap default is overridden. Every component must use custom CSS from the Covered On design system tokens.
2. **No MLPS references.** Zero tolerance. Any surviving MLPS copy, color, or brand element is a launch-blocking finding.
3. **No placeholder endpoints.** Every nav link and action button must route to a real backend view. Dead links are not acceptable.
4. **No `DEBUG=True`.** Gate 0 decision 2.4 applies to all environments including dev.
5. **Role-based templates.** Admin and client views must render different templates. Admin sees all data; client sees only their own.
6. **Accessibility before polish.** Form labels, focus states, heading hierarchy, and reduced motion are not optional.
7. **HTMX for interactivity.** No custom JS for what HTMX handles natively. Avoid adding a frontend framework.
8. **No fake data in production.** Demo/sample data must be clearly flagged. No dummy services assigned to real clients.

---

## 13. Verification Checklist for Web-Dev Handoff

Before marking Phase 4 UI as complete, verify:

- [ ] `site.css` uses the tokens from Section 1 -- no remaining system font stack, `#1A1A1A` text, `#D6DED6` borders, or `6px` radius
- [ ] Google Fonts are loading for both Fraunces and Inter
- [ ] topbar.html renders the Covered On logo, nav links, and user menu
- [ ] Admin dashboard shows stat cards and relevant overview data
- [ ] Client dashboard shows only the current client's services and reports
- [ ] Service list renders as a card grid with status badges
- [ ] Client list (admin) renders as a responsive table with search
- [ ] Report list shows status badges and download/action buttons
- [ ] Empty states render on every list page when no data exists
- [ ] Forms use the form-input, form-label, and form-section classes
- [ ] HTMX filtering works on list pages (search input + hx-target)
- [ ] Mobile nav collapses to hamburger at 720px and below
- [ ] Skip link is present and focusable
- [ ] Keyboard navigation reaches all interactive elements
- [ ] Tab order follows visual page order
- [ ] Focus rings are visible on all interactive elements
- [ ] `prefers-reduced-motion` disables all animations
- [ ] No Bootstrap classes or CDN links in any template
- [ ] No MLPS copy, brand, color, or reference anywhere
- [ ] No placeholder links, dead buttons, or "coming soon" labels
- [ ] Color contrast passes WCAG AA on all text/background combinations
- [ ] All form inputs have associated `<label>` elements
- [ ] Decorative icons use `aria-hidden="true"`
- [ ] Page title is set per template via `{% block title %}`
- [ ] Touch targets are minimum 44px
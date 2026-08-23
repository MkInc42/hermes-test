# Django Tailwind CSS v4 setup helper

Run the helper against an existing Django project:

```bash
/home/black/.hermes/scripts/tailwind-django-v4-setup.py /path/to/project
```

Useful options:

- `--dry-run` previews package, stylesheet, and `.gitignore` changes without writing files or invoking npm.
- `--brand-tokens` uses a small generic `@theme` starter only when `static/src/input.css` does not exist. Existing input files are never overwritten.
- `--help` prints the full command reference.

The helper uses the official Tailwind CSS v4 packages, `tailwindcss` and `@tailwindcss/cli`; the stale `tailwind-cli` package is not used. The current Covered On lockfile resolves both packages to `4.3.3`, and `npm view` confirms `4.3.3` is the current registry version at implementation time. The helper therefore uses exact `4.3.3` pins and `npm install --save-exact` for reproducible builds.

## Private Tailwind Plus component-source plan

Tailwind Plus source must not be scraped, redistributed, or copied into a public library. If Reknown has authorized access, maintain a private, access-controlled local component-source library/cache instead:

1. Refresh source only through an authenticated browser/export workflow performed by an authorized account.
2. Store the private cache outside public repositories with file permissions, encrypted backup, and an audit record of source URL/category, export date, license scope, and project authorization.
3. Index metadata by Tailwind Plus category (for example, application shells, navigation, forms, tables, and feedback) without publishing the licensed source.
4. For each project, copy only the authorized source into a project-private working area, record the adaptation and license context, and make project-specific changes there.
5. Keep this setup helper limited to npm/build plumbing; it intentionally contains no Tailwind Plus component source or scraping logic.

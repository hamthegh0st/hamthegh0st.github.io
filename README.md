# hamthegh0st — Malware Analysis & Reverse Engineering

A personal technical blog covering malware analysis, reverse engineering, Windows internals, unpacking, and low-level security research.

## Stack

- Astro static site generation
- Astro Content Collections for posts, notes, and tags
- Tailwind CSS
- Pagefind for local site search
- GitHub Pages deployment through GitHub Actions

## Local development

Requirements: Node.js 24 and pnpm 10.

```bash
pnpm install --frozen-lockfile
pnpm dev
```

Build and preview:

```bash
pnpm build
pnpm preview
```

Run the project checks:

```bash
pnpm check
```

## Content

- Blog posts: `content/posts/`
- Notes: `content/notes/`
- Tag descriptions: `content/tags/`
- Static files (images, icons, etc.): `public/`

Post front matter is validated by `src/content.config.ts`. The `hidden: true` field removes a post from the home page, post archive, tag listings, RSS feed, and Pagefind search. The direct post URL remains available, but the page is marked `noindex` for search engines.

## Deployment

GitHub Actions validates pull requests and pushes to `main`. The Pages workflow builds the Astro site and deploys the generated `dist/` directory.

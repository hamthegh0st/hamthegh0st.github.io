# hamthegh0st — Malware Analysis & Reverse Engineering

Personal cybersecurity research blog built with [Astro Cactus](https://github.com/chrismwilliams/astro-theme-cactus) v8.3.0.

## Content

Posts live in `content/posts/` and use Astro Content Collections. Existing article URLs are preserved:

- `/posts/xworm-full-analysis/`
- `/posts/brbbot-full-analysis/`
- `/posts/hancitor-full-analysis/`

The original Jekyll sources (`_posts/`, `_config.yml`, layouts, and related files) remain in the repository as a migration backup. Legacy images are served from `public/assets/`.

## Local development

Requires Node.js 24 and pnpm 10.

```sh
pnpm install
pnpm dev
pnpm build
pnpm preview
```

The production build generates the static site in `dist/`, builds Pagefind search, and deploys to GitHub Pages through GitHub Actions.

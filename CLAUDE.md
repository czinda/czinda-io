# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Hugo-based personal blog for Chris Zinda (https://czinda.io/), focused on PKI, identity management, and enterprise security. Uses the PaperMod theme as a Git submodule.

## Commands

```bash
# Local development server with live reload (default port 1313)
hugo server

# Build for production
hugo --minify

# Create new blog post (starts as draft)
hugo new content/posts/post-title.md
```

## Architecture

- **Theme**: PaperMod (submodule in `/themes/PaperMod/`)
- **Configuration**: `/hugo.toml` - site settings, menu, social links
- **Content**: `/content/posts/` - blog posts in Markdown
- **Archetypes**: `/archetypes/default.md` - template for new posts (creates drafts by default)
- **Build output**: `/public/` - generated static files

## Deployment

GitHub Actions workflow (`.github/workflows/hugo.yaml`) automatically builds and deploys to GitHub Pages on push to `main`. Uses Hugo v0.146.0.

## Content Notes

- Posts with `draft = true` in frontmatter are excluded from production builds
- New posts created via `hugo new` are drafts by default
- Use `hugo server -D` to preview drafts locally

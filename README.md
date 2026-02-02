# czinda.io

Personal blog for Chris Zinda, focused on PKI, identity management, and enterprise security.

**Live site:** https://czinda.io/

## Tech Stack

- [Hugo](https://gohugo.io/) - Static site generator
- [PaperMod](https://github.com/adityatelange/hugo-PaperMod) - Hugo theme (Git submodule)
- GitHub Pages - Hosting
- GitHub Actions - CI/CD

## Local Development

### Prerequisites

- [Hugo Extended](https://gohugo.io/installation/) v0.146.0 or later

### Setup

```bash
# Clone with submodules
git clone --recurse-submodules https://github.com/czinda/czinda-io.git
cd czinda-io

# Start development server
hugo server
```

The site will be available at http://localhost:1313/

### Preview Drafts

```bash
hugo server -D
```

## Creating Content

```bash
# Create a new blog post (starts as draft)
hugo new content/posts/my-post-title.md
```

Posts are created as drafts by default. Set `draft = false` in the frontmatter to publish.

## Build

```bash
# Production build
hugo --minify
```

Output is generated in the `/public/` directory.

## Deployment

Pushing to `main` triggers automatic deployment to GitHub Pages via GitHub Actions.

## Project Structure

```
├── archetypes/       # Templates for new content
├── content/posts/    # Blog posts (Markdown)
├── themes/PaperMod/  # Theme (submodule)
├── hugo.toml         # Site configuration
└── .github/workflows # CI/CD
```

## License

Content is copyright Chris Zinda. Theme is MIT licensed.

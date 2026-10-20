# Publishing footballedge-verify (founder checklist)

This folder lives in the FootballEdge monorepo at `tools/verify-pick` and is meant to be its own
**public** GitHub repository (MIT) and, optionally, an npm package. Nothing here has been published
yet. About 15 minutes.

## 1. Create the public GitHub repository

1. On GitHub: **New repository** → owner `footballedge` (or the account you want) → name
   `footballedge-verify` → **Public** → no README, no licence, no .gitignore (they are already here).
2. If the owner or name differs from `footballedge/footballedge-verify`, change `repository.url`
   and `bugs.url` in `package.json` first and commit that in the monorepo.

## 2. Push this folder, with its history, from the monorepo

From the monorepo root, on an up-to-date `main`:

```bash
git subtree split --prefix=tools/verify-pick -b verify-pick-release
git push git@github.com:footballedge/footballedge-verify.git verify-pick-release:main
git branch -D verify-pick-release
```

`git subtree split` makes a branch whose root is this folder and whose commits are only the ones
that touched it, so the public repository contains nothing else from the monorepo. Check before
pushing: `git ls-tree -r --name-only verify-pick-release` must list only `bin/`, `src/`, `test/`,
`.gitignore`, `README.md`, `LICENSE`, `CHANGELOG.md`, `PUBLISHING.md` and `package.json`.

Later releases: commit in the monorepo as usual, then run the same three commands (the push is a
fast-forward).

On GitHub afterwards: add the description ("Check that a FootballEdge pick was sealed before
kick-off") and the website `https://footballedge.io/en/results/proof/verify`.

## 3. Show it on the site

Set `NEXT_PUBLIC_VERIFIER_REPO_URL=https://github.com/footballedge/footballedge-verify` in Vercel
(production) and redeploy. Until it is set, `/results/proof/verify` hides the "One command for all
of it" section, so the page never links to something that does not exist.

## 4. Optional: publish to npm (makes `npx footballedge-verify …` work)

```bash
cd tools/verify-pick
npm test                       # all green (uses openssl if installed)
npm view footballedge-verify   # "404 Not Found" = the name is still free
npm login                      # the FootballEdge npm account, with 2FA
npm pack --dry-run             # must list only LICENSE, README.md, CHANGELOG.md, package.json, bin/, src/
npm publish --access public
```

Then check it from a clean folder: `npx footballedge-verify 6ad6595765497923a6ea0c47` must end
with `Result: PASS`.

New version: bump `version` in `package.json` and `VERSION` in `src/verify.js`, add a
`CHANGELOG.md` entry, commit, `npm publish`, `git tag v<version>` on the public repository.

Until the package is on npm, the README's `npx footballedge-verify` lines do not work; people can run
it from a clone with `node bin/footballedge-verify.js <batch>`.

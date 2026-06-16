# Contributing to @sequesign/sdk

Thanks for your interest in contributing to the Sequesign SDK — the reference
implementation of the Sequesign protocol.

## This repository is a generated mirror

This repo is **generated** from Sequesign's monorepo (the source of truth) and
published to npm; the code under `src/` here is a synced copy. Accepted changes
are integrated upstream by a maintainer and the mirror is regenerated, so a
change is typically _applied_ upstream rather than merged directly here.

Best ways to contribute:

- **Open an issue** describing a bug or a proposed change.
- **Open a pull request** with a small, focused, well-described change; a
  maintainer will review it and integrate it upstream.

## Contributor License Agreement

Contributions require acceptance of a Contributor License Agreement before they
can be accepted:

- Individuals — [`CLA.md`](./CLA.md)
- Companies / entities — [`CCLA.md`](./CCLA.md)

When you open a pull request, the CLA assistant will ask you to accept it. You
**retain ownership** of your contributions; the CLA grants Sequesign a copyright
and patent license (see the agreement).

## Development

The package is standalone and dependency-free at runtime (Node ≥ 22.11):

```bash
npm install        # the mirror ships package.json without a lockfile, so use install (not ci)
npm run build      # tsc -> dist/
npm pack           # produce the publishable tarball
```

## Code style

- TypeScript in `strict` mode.
- Format with Prettier before submitting.

## Security issues

Do **not** open a public issue for a security vulnerability — see
[`SECURITY.md`](./SECURITY.md).

## Code of conduct

This project follows our [Code of Conduct](./CODE_OF_CONDUCT.md). By
participating, you agree to uphold it.

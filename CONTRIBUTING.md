# Contributing to marlinspike-dpi

Thanks for considering a contribution. A few things you should know first.

## License model

`marlinspike-dpi` is dual-licensed under **AGPL-3.0-or-later** and a **commercial licence** (see [LICENSE-COMMERCIAL.md](LICENSE-COMMERCIAL.md)). This lets us:

- Keep the code openly available to defenders, researchers, and open-source projects under AGPL.
- Fund continued development by offering commercial embedding rights to vendors who need them.

To preserve this dual-licence path, **all contributions must be made under terms that allow ERISFORGE Ltd. (the copyright holder) to distribute them under both licences**.

## Contributor agreement

By opening a pull request, you agree that:

1. You wrote the code yourself, or have the right to contribute it.
2. You grant ERISFORGE Ltd. a perpetual, worldwide, royalty-free, irrevocable licence to:
   - Distribute your contribution under the AGPL-3.0-or-later (the existing project licence), and
   - Distribute your contribution under the commercial licence offered by ERISFORGE Ltd. for embedded/closed-source use.
3. You retain copyright on your contribution. This is a licence, not an assignment — you don't transfer ownership.
4. If your employer holds rights to your work, you've checked that they're okay with you contributing under these terms.

This is intentionally a shorter version of a CLA. We don't ask you to sign a separate document — opening the PR signals agreement to the terms above.

If your contribution is small (a typo fix, a comment correction, a documentation tweak) you can skip the signal step — anything under 10 lines of code or 50 words of docs is implicitly de minimis.

If you can't agree to the dual-licence terms (e.g., your employer's IP policy forbids it, you object to commercial licensing of OSS, etc.) — that's fine. Open an issue describing the change you'd like to make and we'll implement it ourselves, or you can fork under AGPL only.

## What we want

- **Protocol dissectors.** OT, IT, anything passive. See `src/engine/decoders/` for the pattern. Lightweight, allocation-conscious, no `unsafe`.
- **Anomaly detectors.** New signatures for stovetop (frame-level), icmpeeker (ICMP), bilgepump (L2 stateful).
- **Fuzz coverage.** Especially for the OT decoders. We use `cargo fuzz`.
- **Performance work.** PRs with benchmark numbers showing measurable improvement on the corpus.
- **Bug fixes.** Always welcome.

## What we want less of

- Architectural rewrites that span >10 files. Discuss in an issue first.
- New dependencies. Every direct dep adds supply-chain surface. If you need a small util, consider inlining.
- Reformatting / style-only changes. Run `cargo fmt` and `cargo clippy` and that's it.

## Dev setup

```sh
cargo build
cargo test
cargo clippy --all-targets
cargo fmt --check
```

For benchmarks: `cargo bench` (uses Criterion, produces HTML reports in `target/criterion/`).

For fuzzing a decoder: `cargo +nightly fuzz run <target>`.

## Releases

Maintainers cut releases. See `CHANGELOG.md` (if present) for the version history.

# Compatibility and evolution

| | |
|---|---|
| Repository | `Varketa/verify-acting-principal` |
| Packages | npm `@varketa/verify-acting-principal`, PyPI `varketa-verify-acting-principal` |
| Recorded release | [0.2.1](https://github.com/Varketa/verify-acting-principal/releases/tag/v0.2.1), published 2026-10-23; its notes record the package and vector digests |
| Claim-set versions accepted | `ver` 3 and 4 (from 0.2.0) |
| Vector version | `v4`, and `v3` with `unknown-ver` superseded |
| Metadata path | `<issuer>/.well-known/varketa-acting-principal` |

- **Semver, tied to `ver`.** Accepting a new `ver` is a minor release; dropping one is a major release.
- **Overlap.** When `ver` N ships, the libraries keep accepting N-1 for at least 60 days, and Varketa keeps signing
  N-1 for any adopter not yet moved until the notice's date.
- **Vectors** are versioned with the claim set (`vectors/v<ver>/`). Each library release names the vector version it
  passes.
- **Next libraries:** Ruby (Rack/Rails) first, then Go (`net/http`) and Java/Kotlin (Spring); C#/.NET later.

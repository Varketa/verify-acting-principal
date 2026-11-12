# Compatibility and evolution

| | |
|---|---|
| Repository | `Varketa/verify-acting-principal` |
| Packages | npm `@varketa/verify-acting-principal`, PyPI `varketa-verify-acting-principal` |
| Recorded release | [0.3.0](https://github.com/Varketa/verify-acting-principal/releases/tag/v0.3.0), published 2026-11-02; its notes record the package and vector digests |
| Claim-set versions accepted | `ver` 3, 4 and 5 (from 0.3.0); 3 and 4 in 0.2.x |
| Vector version | `v5`, and `v4` and `v3` with `unknown-ver` superseded (from 0.3.0); `v4` and `v3` in 0.2.x |
| Metadata path | `<issuer>/.well-known/varketa-acting-principal` |

- **Semver, tied to `ver`.** Accepting a new `ver` is a minor release; dropping one is a major release.
- **Overlap.** When `ver` N ships, the libraries keep accepting N-1 for at least 60 days, and Varketa keeps signing
  N-1 for any adopter not yet moved until the notice's date.
- **Vectors** are versioned with the claim set (`vectors/v<ver>/`). Each library release names the vector version it
  passes.
- **Next libraries:** Ruby (Rack/Rails) first, then Go (`net/http`) and Java/Kotlin (Spring); C#/.NET later.

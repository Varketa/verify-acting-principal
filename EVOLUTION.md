# Compatibility and evolution

| | |
|---|---|
| Repository | `Varketa/verify-acting-principal` |
| Packages | npm `@varketa/verify-acting-principal`, PyPI `varketa-verify-acting-principal` |
| Recorded release | [0.4.0](https://github.com/Varketa/verify-acting-principal/releases/tag/v0.4.0), published 2026-11-21; its notes record the package and vector digests |
| Claim-set versions accepted | `ver` 3, 4, 5 and 6 (from 0.4.0); 3, 4 and 5 in 0.3.x; 3 and 4 in 0.2.x |
| Vector version | `v6`, and `v5`, `v4` and `v3` with `unknown-ver` superseded (from 0.4.0); `v5`, `v4` and `v3` in 0.3.x; `v4` and `v3` in 0.2.x |
| Metadata path | `<issuer>/.well-known/varketa-acting-principal` |

- **Semver, tied to `ver`.** Accepting a new `ver` is a minor release; dropping one is a major release.
- **Overlap.** When `ver` N ships, the libraries keep accepting N-1 for at least 60 days, and Varketa keeps signing
  N-1 for any adopter not yet moved until the notice's date.
- **Vectors** are versioned with the claim set (`vectors/v<ver>/`). Each library release names the vector version it
  passes.
- **Next libraries:** Ruby (Rack/Rails) first, then Go (`net/http`) and Java/Kotlin (Spring); C#/.NET later.

## Changes by release

### 0.4.0

- **Changed (security).** A clock that reads earlier than a document's fetch now counts that document as past its
  max-age (SPEC §2.3; #30). In 0.3.0 and 0.2.1, both libraries kept a cached metadata document and JWK Set fresh while
  the clock stood behind the fetch, so a key rotated out of the set stayed trusted past the cache lifetime. Affected:
  0.3.0 and 0.2.1.

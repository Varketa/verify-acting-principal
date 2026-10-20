# verify-acting-principal

Verify the `Varketa-Acting-Principal` header on an API that Varketa's agents call. The header says on whose behalf a
call is made and for which of your customer orgs, bound to that one request.

- [SPEC.md](https://github.com/Varketa/verify-acting-principal/blob/main/SPEC.md): the language-neutral specification.
- [vectors/v4](https://github.com/Varketa/verify-acting-principal/tree/main/vectors/v4) and [vectors/v3](https://github.com/Varketa/verify-acting-principal/tree/main/vectors/v3): the signed test vectors, the normative half. Every library
  here passes both, `v3`'s `unknown-ver` superseded ([SPEC §6](https://github.com/Varketa/verify-acting-principal/blob/main/SPEC.md#6-the-vectors)).
- [js](https://github.com/Varketa/verify-acting-principal/tree/main/js): TypeScript / Node (`@varketa/verify-acting-principal`), no runtime dependencies.
- [python](https://github.com/Varketa/verify-acting-principal/tree/main/python): Python (`varketa-verify-acting-principal`), on `cryptography`.

Install with `npm install @varketa/verify-acting-principal` or `pip install varketa-verify-acting-principal`.
Releases are published from a signed tag ([RELEASING.md](https://github.com/Varketa/verify-acting-principal/blob/main/RELEASING.md)), and
[EVOLUTION.md](https://github.com/Varketa/verify-acting-principal/blob/main/EVOLUTION.md) says which versions are published.

```ts
import { Verifier, InMemoryReplayStore } from "@varketa/verify-acting-principal";

const verifier = new Verifier({
  issuer: "https://api.varketa.ai",
  adopter: process.env.VARKETA_ADOPTER_ID!,
  audience: "https://api.example.com",
  replayStore: new InMemoryReplayStore({ singleInstance: true }), // one instance only; otherwise a shared store
});
const identity = await verifier.verify({ method: req.method, url: fullUrl, body: rawBody, assertion: req.headers["varketa-acting-principal"] });
// authorize every record against identity.tenant
```

```python
from varketa_verify_acting_principal import Verifier, InMemoryReplayStore

verifier = Verifier(issuer="https://api.varketa.ai", adopter=ADOPTER_ID, audience="https://api.example.com",
                    replay_store=InMemoryReplayStore(single_instance=True))
identity = verifier.verify(method=request.method, url=full_url, body=raw_body,
                           assertion=request.headers.get("Varketa-Acting-Principal"))
```

A refusal raises `VerificationError` with one code from SPEC.md §3. Answer it with 401 or 403.

Contributions: this repository does not take issues or pull requests.

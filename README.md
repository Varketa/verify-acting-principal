# verify-acting-principal

Verify the `Varketa-Acting-Principal` header on an API that Varketa's agents call. The header says on whose behalf a
call is made and for which of your customer orgs, bound to that one request.

- [SPEC.md](SPEC.md): the language-neutral specification.
- [vectors/v3](vectors/v3): the signed test vectors, the normative half. Every library here passes all of them.
- [js](js): TypeScript / Node (`@varketa/verify-acting-principal`), no runtime dependencies.
- [python](python): Python (`varketa-verify-acting-principal`), on `cryptography`.

The packages are not yet published to npm or PyPI.

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

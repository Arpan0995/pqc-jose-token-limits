# Findings — PQ Signatures in JOSE/JWT Token Plumbing

Run: July 2026, Corretto JDK 24.0.2 (Apple Silicon), BouncyCastle 1.85.
Raw data: `token-sizes.csv`, `server-defaults.csv`, `sign-verify-bench.csv`,
`provider-matrix.csv`.

## Headline results

1. **ML-DSA-65 — the CNSA 2.0 workhorse parameter set — never fits in a cookie.**
   Even the minimal RFC 9068 profile with the leanest (`kid`) header produces a
   4,812-byte token; with the `__Host-session=` prefix that exceeds the 4,096-byte
   RFC 6265 cookie capacity. Every browser-cookie-based session pattern (BFF
   pattern included) breaks at this parameter set with a plain JWS.

2. **ML-DSA-44 and ML-DSA-65 bearer tokens pass every tested server at defaults;
   ML-DSA-87 is the first parameter set to produce live rejections.** The
   8,855-byte ML-DSA-87 enterprise-profile token was rejected by Jetty 12 (431),
   Tomcat 10.1 (400 + `IllegalArgumentException: Request header is too large` in
   the log), and stock Netty (decoder failure), while passing Undertow.

3. **Every SLH-DSA token was rejected by three of the four servers** — including
   the *minimal* profile at the *smallest* parameter set (SLH-DSA-SHA2-128s,
   10,886 B). SLH-DSA cannot be carried as an HTTP bearer token through
   default-configured Java infrastructure at all.

4. **Undertow is the outlier: its default header ceiling is ~1 MiB (measured
   1,048,498-byte token accepted) vs ~8 KiB for the other three.** A fleet
   migrating to PQ tokens behind mixed infrastructure will see *inconsistent*
   failures: requests succeed on Undertow-based services and die with 400/431 on
   Jetty/Tomcat/Netty-based ones. The same 8 KiB-ish ceilings differ by up to 52
   bytes between servers (8,166 / 8,114 / 8,138), so a token can even pass one
   servlet container and fail another.

5. **The cost of ML-DSA at the token layer is bytes, not CPU** — consistent with
   the companion X.509 certpath study. ML-DSA sign/verify medians (155–323 µs /
   67–118 µs) sit inside the classical envelope (RS256 sign is *slower* at
   ~610–646 µs). **SLH-DSA-SHA2-128s signing is the exception: 522 ms per token**,
   which disqualifies it for online token issuance regardless of transport limits
   (128f trades that to 23 ms at +9 KiB of signature).

## E1 — token sizes vs documented limits (kid header, bytes)

| alg | sig (raw) | minimal | oidc-id | enterprise | cookie 4096 | 8 KiB line | APIGW 10240 |
|---|---|---|---|---|---|---|---|
| ES256 | 64 | 481 | 785 | 2,766 | all | all | all |
| EdDSA | 64 | 481 | 785 | 2,766 | all | all | all |
| RS256 | 256 | 737 | 1,041 | 3,022 | all | all | all |
| ML-DSA-44 | 2,420 | 3,627 | 3,931 | 5,912 | minimal, oidc only | all | all |
| ML-DSA-65 | 3,309 | 4,812 | 5,116 | 7,097 | **none** | all | all |
| ML-DSA-87 | 4,627 | 6,570 | 6,874 | 8,855 | **none** | minimal, oidc only | all |
| SLH-DSA-128s | 7,856 | 10,886 | 11,190 | 13,171 | **none** | **none** | **none** |
| SLH-DSA-128f | 17,088 | 23,195 | 23,499 | 25,480 | **none** | **none** | **none** |

Header-variant deltas (minimal profile): embedding the public key (`jwk`) adds
2,412 B (ML-DSA-44) to 4,687 B (ML-DSA-87) and pushes ML-DSA-65 past the 8 KiB
line (8,362 B); embedding a certificate (`x5c`) yields 10.7–25.4 KB tokens for the
PQ algorithms — over the AWS API Gateway limit in every PQ case. PQ tokens must
ship keys by reference (`kid` + JWKS); the self-describing-token patterns do not
survive.

## E2 — live behaviour at server defaults

| server | version | empirical max token | ML-DSA-44/65 | ML-DSA-87 ent. | SLH-DSA (all) |
|---|---|---|---|---|---|
| Jetty | 12.0.16 | 8,166 B | 200 | **431** | **431** |
| Tomcat | 10.1.34 | 8,114 B | 200 | **400** | **400** |
| Undertow | 2.3.18 | 1,048,498 B | 200 | 200 | 200 |
| Netty (stock codec) | 4.1.115 | 8,138 B | 200 | **rejected** (decoder failure → 431) | **rejected** |

Note the failure-mode inconsistency itself: the same oversized token surfaces as
431, 400, or a decoder-level kill depending on the stack — relevant to anyone
writing migration runbooks or alerting rules.

## E3 — per-token latency, median (µs)

| alg | provider | sign | verify |
|---|---|---|---|
| RS256 | SunRsaSign / BC | 646 / 610 | 34 / 32 |
| ES256 | SunEC / BC | 133 / 120 | 339 / 115 |
| EdDSA | SunEC / BC | 398 / 47 | 336 / 71 |
| ML-DSA-44 | SUN (JDK 24) / BC | 323 / 155 | 73 / 68 |
| ML-DSA-65 | SUN / BC | 265 / 214 | 72 / 101 |
| ML-DSA-87 | SUN / BC | 313 / 270 | 111 / 118 |
| SLH-DSA-128s | BC | **521,785** | 483 |
| SLH-DSA-128f | BC | 23,247 | 1,324 |

Provider matrix: ML-DSA is offered by both BC and the JDK 24 `SUN` provider
(JEP 497) — and a BC-signed ML-DSA-65 token verifies under the JDK provider
(cross-provider test in `RoundTripTest`). SLH-DSA is BC-only on this JVM.

## What restores compatibility (from the E1 data)

| mitigation | effect measured |
|---|---|
| Drop to ML-DSA-44 | −1,185 B vs -65; restores *cookie* fit for minimal/oidc profiles only |
| `kid` instead of `jwk`/`x5c` | −2.4 KB to −21 KB; mandatory for PQ, sufficient to keep ML-DSA-44/65 under every 8 KiB header limit |
| Trim enterprise claims (groups by reference) | −2.3 KB payload; moves ML-DSA-87 back under the 8 KiB ceilings |
| Token-by-reference (opaque handle + introspection) | sidesteps all limits; the only pattern that carries SLH-DSA |
| SLH-DSA-128f instead of -128s for issuance latency | 522 ms → 23 ms sign, but +12.3 KB token — solves the CPU problem by worsening the fatal size problem |

## Follow-up work

- HTTP/2 HPACK/QPACK: how much of the base64url signature survives Huffman
  compression (expected: little — the signature is high-entropy).
- Spring Cloud Gateway / Kong / Envoy as intermediaries (proxy default limits).
- CWT/COSE comparison: CBOR encoding saves the 33% base64 tax; quantify end-to-end.
- Detached-payload JWS (RFC 7797) and split-token patterns for the cookie case.

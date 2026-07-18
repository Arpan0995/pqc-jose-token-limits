# Findings — PQ Signatures in JOSE/JWT Token Plumbing

Run: July 2026, Corretto JDK 24.0.2 (Apple Silicon), BouncyCastle 1.85.
Raw data: `token-sizes.csv`, `server-defaults.csv`, `sign-verify-bench.csv`,
`provider-matrix.csv`, `cose-vs-jose.csv`, `hpack.csv`, `hpack-table-sweep.csv`.

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

5. **CWT/COSE recovers 26–28% for PQ tokens in binary form — but only 2–4% once
   the CWT is re-base64url'd for an HTTP header.** CBOR kills the base64 tax only
   on transports that carry binary (CoAP/OSCORE, MQTT, gRPC binary metadata); in
   HTTP headers the signature re-pays the tax and only the CBOR claims compaction
   survives. Notably, a binary ML-DSA-65 minimal CWT (3,494 B) *would* fit the
   4,096-byte cookie budget — but cookies are ASCII, and its base64 form (4,659 B)
   does not. COSE cannot rescue the cookie.

6. **HPACK's Huffman table claws back a uniform ~19–20% from base64url tokens**
   (an ML-DSA-65 minimal bearer goes 4,819 → 3,853 B on the wire) — but this
   saves *bandwidth only*: HTTP/2's `SETTINGS_MAX_HEADER_LIST_SIZE` and every
   server limit in E2 are enforced on **uncompressed** octets (RFC 7540 §6.5.2),
   so compression buys zero headroom against the limits measured in E1/E2.

7. **The HPACK dynamic-table cliff is the sharpest PQ penalty found in this
   study.** An indexed header entry costs name+value+32 bytes of the 4,096-byte
   default dynamic table. Classical bearer tokens fit, get indexed once, and cost
   **1 byte per request** from the second request on. Every ML-DSA-65, ML-DSA-87,
   and SLH-DSA token — and ML-DSA-44 with enterprise claims — exceeds the table
   and **can never be indexed**: each request re-pays the full Huffman'd literal
   (3,853–20,391 B). Steady-state per-request wire cost of ML-DSA-65 vs classical
   is therefore ~3,900:1, not the ~7:1 the raw token sizes suggest. ML-DSA-44
   with lean claims is the last configuration that rides HTTP/2 efficiently.

8. **The HPACK cliff has a one-line fix with a quantified price: raising
   SETTINGS_HEADER_TABLE_SIZE to 8 KiB restores full indexing for every ML-DSA-44
   and ML-DSA-65 token** (16 KiB adds ML-DSA-87 enterprise and SLH-DSA-128s;
   32 KiB covers everything tested). Once indexed, steady state returns to
   ~1 byte/request, saving 3.8–20 KB per request; the extra table memory pays for
   itself in wire bytes within 2–3 requests on a connection. The cost is
   per-connection decoder memory (×4 at 16 KiB), which a high-concurrency
   gateway multiplies by its connection count — a real but bounded price, and
   the single most effective HTTP/2 mitigation this study found.

9. **The cost of ML-DSA at the token layer is bytes, not CPU** — consistent with
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

## E4 — CWT/COSE_Sign1 vs compact JWS (bytes)

| alg | profile | JWS | COSE (binary) | savings | b64url(COSE) | savings in header |
|---|---|---|---|---|---|---|
| ES256 | minimal | 481 | 247 | 48.6% | 330 | 31.4% |
| ES256 | enterprise | 2,766 | 1,907 | 31.1% | 2,543 | 8.1% |
| ML-DSA-44 | minimal | 3,627 | 2,605 | 28.2% | 3,474 | 4.2% |
| ML-DSA-65 | minimal | 4,812 | 3,494 | 27.4% | 4,659 | 3.2% |
| ML-DSA-65 | enterprise | 7,097 | 5,154 | 27.4% | 6,872 | 3.2% |
| ML-DSA-87 | minimal | 6,570 | 4,812 | 26.8% | 6,416 | 2.3% |
| SLH-DSA-128s | minimal | 10,886 | 8,041 | 26.1% | 10,722 | 1.5% |
| SLH-DSA-128f | enterprise | 25,480 | 18,933 | 25.7% | 25,244 | 0.9% |

The pattern inverts between families: for classical tokens the payload dominates,
so CBOR claim compaction keeps 8–31% even after re-base64url; for PQ tokens the
signature dominates, so the in-header savings shrink *as the signature grows*
(4.2% → 0.9%). Full grid in `cose-vs-jose.csv`.

## E5 — HPACK (RFC 7541) at the default 4,096 B dynamic table

| alg | profile | value B | Huffman'd | savings | req 2 | req 3 | indexable |
|---|---|---|---|---|---|---|---|
| RS256 | minimal | 744 | 600 | 19.4% | 1 | 1 | yes |
| ES256 | enterprise | 2,773 | 2,247 | 19.0% | 1 | 1 | yes |
| ML-DSA-44 | minimal | 3,634 | 2,905 | 20.1% | 1 | 1 | yes |
| ML-DSA-44 | oidc-id | 3,938 | 3,162 | 19.7% | 1 | 1 | yes |
| ML-DSA-44 | enterprise | 5,919 | 4,755 | 19.7% | 4,755 | 4,755 | **no** |
| ML-DSA-65 | minimal | 4,819 | 3,853 | 20.0% | 3,853 | 3,853 | **no** |
| ML-DSA-87 | enterprise | 8,862 | 7,109 | 19.8% | 7,109 | 7,109 | **no** |
| SLH-DSA-128f | enterprise | 25,487 | 20,391 | 20.0% | 20,391 | 20,391 | **no** |

The indexability cutline (entry = name + value + 32 ≤ 4,096) falls exactly
between ML-DSA-44 lean tokens (indexed; 1 B/request steady state) and everything
larger (never indexed; full literal every request). Footnote: the two small
ES256/EdDSA minimal rows in `hpack.csv` show ≈0% Huffman savings because Netty's
encoder skips Huffman below 512 B as a CPU optimization; browsers and nghttp2
Huffman-encode regardless, so ~19–20% is the transferable figure. QPACK (HTTP/3,
RFC 9204) shares the static Huffman table and dynamic-table economics.

## E6 — SETTINGS_HEADER_TABLE_SIZE sweep

Smallest swept table size at which each token class becomes indexable (entry =
name + value + 32; steady state ~1 B/request once indexed):

| table size | newly indexable | wire saved per request | payback (requests) |
|---|---|---|---|
| 4 KiB (default) | all classical; ML-DSA-44 minimal/oidc | — | — |
| 8 KiB | ML-DSA-44 enterprise; **all ML-DSA-65**; ML-DSA-87 minimal/oidc | 3,847–5,703 B | 2–3 |
| 16 KiB | ML-DSA-87 enterprise; all SLH-DSA-128s | 7,098–10,582 B | 2–3 |
| 32 KiB | all SLH-DSA-128f | 18,549–20,390 B | 2 |

Full grid (5 table sizes × 24 tokens) in `hpack-table-sweep.csv`. Request 1
includes the dynamic-table-size-update bytes emitted by the resize.

## What restores compatibility (from the E1 data)

| mitigation | effect measured |
|---|---|
| Drop to ML-DSA-44 | −1,185 B vs -65; restores *cookie* fit for minimal/oidc profiles only — and (E5) is the only PQ set that stays HPACK-indexable |
| `kid` instead of `jwk`/`x5c` | −2.4 KB to −21 KB; mandatory for PQ, sufficient to keep ML-DSA-44/65 under every 8 KiB header limit |
| Trim enterprise claims (groups by reference) | −2.3 KB payload; moves ML-DSA-87 back under the 8 KiB ceilings, ML-DSA-44 back under the HPACK indexability line |
| CWT/COSE instead of JWT (E4) | −26–28% on binary transports; only −2–4% in HTTP headers — does not rescue the ML-DSA-65 cookie |
| HTTP/2 HPACK (E5) | −19–20% bandwidth; zero headroom against limits (enforced on uncompressed octets); indexing benefit unavailable to any token ≥ ML-DSA-65 at the default table |
| Raise SETTINGS_HEADER_TABLE_SIZE (E6) | 8 KiB re-indexes all ML-DSA-44/65 (steady state ~1 B/req, payback in 2–3 requests); cost is per-connection decoder memory × fleet concurrency |
| Token-by-reference (opaque handle + introspection) | sidesteps all limits; the only pattern that carries SLH-DSA |
| SLH-DSA-128f instead of -128s for issuance latency | 522 ms → 23 ms sign, but +12.3 KB token — solves the CPU problem by worsening the fatal size problem |

## Follow-up work

- Spring Cloud Gateway / Kong / Envoy as intermediaries (proxy default limits,
  whether they mark `authorization` never-indexed, and whether their
  SETTINGS_HEADER_TABLE_SIZE is even configurable — the E6 fix is only available
  where the knob exists).
- Detached-payload JWS (RFC 7797) and split-token/cookie-sharding patterns.
- CWT end-to-end on a genuinely binary transport (gRPC metadata-bin, MQTT v5).

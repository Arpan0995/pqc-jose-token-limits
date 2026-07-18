# pqc-jose-token-limits

**Do post-quantum signatures fit in the token plumbing of real backends?**
An empirical study of ML-DSA (FIPS 204) and SLH-DSA (FIPS 205) signed JWTs against
the cookie caps, header buffers, and gateway limits that token-based authentication
actually rides on — measured in Java, against live embedded servers.

## Why

The IETF COSE/JOSE working group is standardizing post-quantum `alg` values
(draft-ietf-cose-dilithium, draft-ietf-cose-sphincs-plus). A JWT that today carries
a 64-byte ES256 signature will carry 2,420–17,088 bytes of ML-DSA/SLH-DSA signature —
before base64url's 4/3 expansion. The transport underneath (RFC 6265's 4,096-byte
cookie capacity, 8 KiB header buffers in nginx/Apache/Jetty/Tomcat/Netty, AWS API
Gateway's 10,240-byte combined-header limit) was never sized for that. This project
measures exactly where the plumbing breaks and what restores compatibility —
deployment-planning data that U.S. enterprises and agencies migrating under NIST's
2035 PQC mandate and NSA CNSA 2.0 need for the *authorization* layer, not just TLS.

## Headline findings (July 2026 run)

- **ML-DSA-65 never fits in a cookie** — even a minimal RFC 9068 access token with a
  bare `kid` header is 4,812 B, over the RFC 6265 per-cookie capacity. Browser-session
  patterns break at the CNSA 2.0 default parameter set.
- **ML-DSA-44/65 bearer tokens pass all four embedded Java servers at default
  config; ML-DSA-87 enterprise tokens and *all* SLH-DSA tokens are rejected by
  Jetty (431), Tomcat (400), and stock Netty (decoder kill)** — while Undertow's
  default ceiling is ~1 MiB, so mixed fleets fail *inconsistently*.
- **ML-DSA costs bytes, not CPU** (sign 155–323 µs, inside the classical envelope;
  RS256 is slower), but **SLH-DSA-SHA2-128s signing costs 522 ms per token** —
  unusable for online issuance independent of any size limit.
- **CWT/COSE recovers 26–28% of PQ token size in binary form, but only 2–4% once
  re-base64url'd into an HTTP header** — CBOR kills the base64 tax only on
  binary-capable transports, and does not rescue the ML-DSA-65 cookie.
- **HPACK Huffman saves a uniform ~20% of bandwidth but zero limit headroom**
  (HTTP/2 limits count uncompressed octets) — and the sharpest finding: every
  token ≥ ML-DSA-65 **exceeds HPACK's 4,096-byte dynamic table and can never be
  indexed**. Classical tokens cost 1 byte/request after the first; ML-DSA-65
  re-pays ~3.9 KB on every request — a ~3,900:1 steady-state wire-cost ratio.
- Key-by-value patterns (`jwk`, `x5c` headers) add 2.4–21 KB and are dead on
  arrival for PQ; keys must travel by reference (`kid` + JWKS).
- A BC-signed ML-DSA-65 token verifies under the JDK 24 built-in provider
  (JEP 497) — the two Java ML-DSA stacks interoperate at the JWS layer.

Full analysis: [results/FINDINGS.md](results/FINDINGS.md).
Method and threats to validity: [docs/EXPERIMENT-DESIGN.md](docs/EXPERIMENT-DESIGN.md).

## What's here

| experiment | question | output |
|---|---|---|
| **E1** `sizes` | token size per algorithm × claim profile × header variant vs documented limits | `results/token-sizes.csv`, `results/provider-matrix.csv` |
| **E2** `servers` | accept/reject at Jetty/Tomcat/Undertow/Netty **defaults** + empirical header ceiling (binary search) | `results/server-defaults.csv` |
| **E3** `bench` | per-token sign/verify latency, BouncyCastle vs JDK 24 built-ins | `results/sign-verify-bench.csv` |
| **E4** `cose` | byte-exact CWT/COSE_Sign1 (RFC 8392/9052) vs compact JWS — binary and re-base64url'd | `results/cose-vs-jose.csv` |
| **E5** `hpack` | HPACK Huffman savings + dynamic-table indexability (per-request steady-state cost) | `results/hpack.csv` |

Supporting code: byte-exact compact-JWS construction over `java.security.Signature`
(`CompactJws`), draft "AKP" JWKs for PQ keys (`Jwks`), and a working
`JWSSigner`/`JWSVerifier` pair that adds the draft PQ algorithms to an unmodified
Nimbus JOSE+JWT stack (`NimbusJcaSigner`/`NimbusJcaVerifier`, exercised in
`RoundTripTest`, including BC→JDK cross-provider verification).

## Run it

Requires JDK 21+ (JDK 24+ adds the built-in ML-DSA provider to the comparison) and Maven.

```bash
mvn package
java -jar target/pqc-jose-token-limits-0.1.0-SNAPSHOT.jar all     # or: sizes | servers | bench | cose | hpack
```

E2 starts four embedded servers on ephemeral localhost ports, one at a time.
Full run takes ~2–3 minutes; SLH-DSA-128s signing dominates the bench time.

## Scope notes

The PQ JOSE identifiers are IETF **drafts** (pinned in `SigAlg.java`), and the
PQ COSE algorithm numbers are draft/provisional (pinned in `CoseSign1.java`);
sizes are dictated by FIPS 204/205 and are stable regardless of final
identifiers. nginx/Apache/AWS limits are taken from their documentation; the four
Java servers and the HPACK encoder are measured live. See the threats-to-validity
section in the design doc before citing numbers.

## Related work in this series

- [pqc-pki-certpath](https://github.com/Arpan0995/pqc-pki-certpath) — the same
  bytes-not-CPU question at the X.509/PKI layer
- [pqc-composite-signatures](https://github.com/Arpan0995/pqc-composite-signatures) —
  composite ML-DSA + classical signatures (LAMPS draft-19)
- [pqc-hybrid-vs-classical](https://github.com/Arpan0995/pqc-hybrid-vs-classical) —
  hybrid key exchange in TLS 1.3
- [pqc-decode-fuzzing](https://github.com/Arpan0995/pqc-decode-fuzzing) — robustness
  of PQC decode/verify paths in Java providers

## License

Apache-2.0

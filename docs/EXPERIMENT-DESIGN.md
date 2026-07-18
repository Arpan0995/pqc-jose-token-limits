# Experiment Design — Post-Quantum Signatures in JOSE/JWT Token Plumbing

## Motivation

Token-based authentication (JWT/JOSE, RFC 7515/7519) is the dominant authorization
mechanism in microservice and API backends. The infrastructure it rides on — cookie
jars, HTTP header buffers, API-gateway limits — was sized in an era of 64–256-byte
signatures. FIPS 204 (ML-DSA) signatures are 2,420–4,627 bytes; FIPS 205 (SLH-DSA)
signatures are 7,856–17,088 bytes at the 128-bit security level alone. The IETF
COSE/JOSE working group is standardizing ML-DSA and SLH-DSA "alg" values
(draft-ietf-cose-dilithium, draft-ietf-cose-sphincs-plus), which makes the question
concrete: **where exactly does the token plumbing of a real Java backend break when
tokens carry post-quantum signatures, and which mitigations restore compatibility?**

No published study measures this empirically. This repository is that experiment.

## Research questions

- **RQ1 (sizes vs limits):** For realistic OAuth 2.0 / OIDC claim profiles, which
  combinations of algorithm × header variant exceed documented transport limits
  (RFC 6265 cookie capacity, nginx/Apache/servlet-container header buffers, AWS
  API Gateway's combined-header limit)?
- **RQ2 (real behaviour at defaults):** What do the four mainstream embedded Java
  HTTP servers (Jetty, Tomcat, Undertow, Netty) actually do with PQ-signed bearer
  tokens at out-of-the-box configuration, and what is each server's empirical
  header ceiling?
- **RQ3 (CPU cost):** Is the per-token sign/verify cost of ML-DSA/SLH-DSA material
  compared to classical algorithms, across the two JCA providers now shipping them
  (BouncyCastle 1.85 and the JDK 24 built-ins, JEP 497)?

## Factors

**Algorithms (8).** Classical baselines RS256 (RSA-2048), ES256 (P-256), EdDSA
(Ed25519); ML-DSA-44/65/87 (FIPS 204); SLH-DSA-SHA2-128s and -128f (FIPS 205).
JOSE `alg` identifiers for the PQ algorithms follow the IETF drafts as of July 2026
and are pinned in `SigAlg.java`.

**Claim profiles (3), byte-identical across algorithms** (`ClaimProfiles.java`):

| profile | model | payload content |
|---|---|---|
| `minimal-access` | RFC 9068 access token | iss/sub/aud/exp/iat/jti/client_id/scope |
| `oidc-id-token` | typical OIDC ID token | + auth_time/nonce/acr/amr/azp + profile claims |
| `enterprise-access` | directory-bloated AT | + 25 AD-style group DNs, roles, tenant claims (Azure AD/Okta pattern) |

**Header variants (3).** `kid` (key by reference — leanest), `jwk` (public key
embedded per RFC 7515 §4.1.3; PQ keys use the draft "AKP" key type), `x5c`
(self-signed certificate embedded, standard base64 per §4.1.6).

**Limits checked (E1).** 4096 B (RFC 6265 §6.1 minimum per-cookie capacity, the
de-facto browser cap on name+value); 8192 B (nginx `large_client_header_buffers`
default — one header line per buffer — and the common Java-server default); 8190 B
(Apache httpd `LimitRequestFieldSize` default); 10240 B (AWS API Gateway documented
combined-header limit). The Authorization line is counted as
`"Authorization: Bearer " + token`, the cookie pair as `"__Host-session=" + token`.

**Servers probed (E2).** Jetty 12.0.16, Tomcat 10.1.34, Undertow 2.3.18, Netty
4.1.115 (`HttpServerCodec` stock constructor), each started programmatically with
**no limit-related configuration touched**, probed with a raw-socket HTTP/1.1
client (deliberately not `java.net.http.HttpClient`, which has its own limits).
Per server: one probe per (algorithm × profile) bearer token with the `kid`
header, then a binary search with synthetic tokens for the largest accepted token
size in [64 B, 2 MiB].

**Bench protocol (E3).** Timed operation = the full per-request path
(`Signature.getInstance` + init + update + sign/verify) over the OIDC ID-token
signing input. 10 warmup iterations, then up to 200 iterations or 3 s per
(algorithm, provider, operation), minimum 10; report median/p10/p90. Every
provider that offers the algorithm is measured (BC, SunRsaSign, SunEC, and the
JDK 24 `SUN` ML-DSA implementation).

## Fixed environment

Apple Silicon macOS, Amazon Corretto JDK 24.0.2, BouncyCastle 1.85, single machine,
no containerization. `iat`/`exp` are fixed constants so payloads are byte-stable
across runs and algorithms.

## Threats to validity

- The PQ JOSE `alg`/`kty` identifiers are **drafts**; names may change before RFC
  publication. Sizes are unaffected (they are dictated by FIPS 204/205 signature
  and key lengths plus base64url's 4/3 expansion).
- E3 is a median-of-N single-machine microbenchmark, not a JMH campaign; it is
  meant to establish orders of magnitude, and its classical-side numbers are
  consistent with the JMH results in the companion PQC-Java-Library-Comparison
  work.
- E2 measures the four *embedded Java* servers empirically; nginx/Apache/AWS
  numbers in E1 come from their documentation, not from live instances.
- The `x5c` variant embeds a single self-signed certificate; production chains
  (leaf + intermediate) would be strictly larger, so its failures are conservative.
- The Netty target answers oversized headers with 431 in the test handler; the
  8 KiB rejection itself comes from the stock `HttpServerCodec` decoder limit.

# Experiment Design - Post-Quantum Signatures in JOSE/JWT Token Plumbing

## Motivation

Token-based authentication (JWT/JOSE, RFC 7515/7519) is the dominant authorization
mechanism in microservice and API backends. The infrastructure it rides on - cookie
jars, HTTP header buffers, API-gateway limits - was sized in an era of 64-256-byte
signatures. FIPS 204 (ML-DSA) signatures are 2,420-4,627 bytes; FIPS 205 (SLH-DSA)
signatures are 7,856-17,088 bytes at the 128-bit security level alone. The IETF
has standardized ML-DSA "alg" values for JOSE and COSE (RFC 9964, May 2026) and is
standardizing SLH-DSA's (draft-ietf-cose-sphincs-plus), which makes the question
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
- **RQ4 (CWT/COSE):** How much of the JOSE overhead - the base64url 4/3 tax on the
  signature plus JSON claim encoding - does CWT/COSE_Sign1 (RFC 8392 / RFC 9052)
  recover, and how much of that advantage survives when the CWT itself must ride
  an HTTP header and be re-base64url'd?
- **RQ5 (HPACK):** What does HTTP/2 header compression (RFC 7541) do for PQ bearer
  tokens - how much does the static Huffman table claw back from base64url text,
  and can PQ tokens be indexed in the default 4,096-byte dynamic table at all
  (i.e., what is the steady-state per-request wire cost)?
- **RQ6 (table sizing):** How large must SETTINGS_HEADER_TABLE_SIZE be to restore
  dynamic-table indexing for each PQ token class, and what is the trade -
  per-connection decoder memory committed vs literal bytes saved per request
  (payback horizon)?

## Factors

**Algorithms (8).** Classical baselines RS256 (RSA-2048), ES256 (P-256), EdDSA
(Ed25519); ML-DSA-44/65/87 (FIPS 204); SLH-DSA-SHA2-128s and -128f (FIPS 205).
JOSE `alg` identifiers: ML-DSA per RFC 9964; SLH-DSA per the active IETF draft as
of July 2026, pinned in `SigAlg.java`.

**Claim profiles (3), byte-identical across algorithms** (`ClaimProfiles.java`):

| profile | model | payload content |
|---|---|---|
| `minimal-access` | RFC 9068 access token | iss/sub/aud/exp/iat/jti/client_id/scope |
| `oidc-id-token` | typical OIDC ID token | + auth_time/nonce/acr/amr/azp + profile claims |
| `enterprise-access` | directory-bloated AT | + 25 AD-style group DNs, roles, tenant claims (Azure AD/Okta pattern) |

**Header variants (3).** `kid` (key by reference - leanest), `jwk` (public key
embedded per RFC 7515 §4.1.3; PQ keys use the draft "AKP" key type), `x5c`
(self-signed certificate embedded, standard base64 per §4.1.6).

**Limits checked (E1).** 4096 B (RFC 6265 §6.1 minimum per-cookie capacity, the
de-facto browser cap on name+value); 8192 B (nginx `large_client_header_buffers`
default - one header line per buffer - and the common Java-server default); 8190 B
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

**CWT/COSE construction (E4).** Same keys, same claim content, same 8-byte kid,
signed both ways. The COSE side is a byte-exact COSE_Sign1 (tag 18): `alg` in the
protected header, `kid` (label 4, bstr) unprotected, CWT claims map as payload.
Registered claims move to RFC 8392 integer keys (iss=1 … cti=7, scope=9 per
RFC 9200; jti becomes cti with the UUID as 16 raw bytes); unregistered claims keep
text keys. COSE `alg` identifiers: ES256=-7, EdDSA=-8, RS256=-257 (RFC 8812);
ML-DSA -48/-49/-50 per RFC 9964; SLH-DSA values are provisional
placeholders - registry outcomes change 1-2 bytes at most. Two comparisons are
reported: binary COSE vs ASCII compact JWS (binary transports: CoAP/OSCORE, MQTT,
gRPC binary metadata), and base64url(COSE) vs compact JWS (HTTP-header reality).
Every COSE_Sign1 is verified by recomputing the Sig_structure before measurement.

**HPACK protocol (E5).** Netty's `DefaultHttp2HeadersEncoder` at the RFC 7541
default 4,096-byte dynamic table, encoding the `authorization` header alone so
byte counts isolate the token. Two sensitivity modes: ALWAYS_SENSITIVE gives the
never-indexed literal (pure Huffman effect, the cost paid on *every* request when
indexing is unavailable or disallowed); NEVER_SENSITIVE allows indexing, and three
consecutive encodings on one encoder reveal whether the entry was indexed
(requests 2-3 collapse to ~1 byte) or not (full literal cost repeats). Entry
indexability is also derived analytically: name + value + 32 ≤ 4,096 (RFC 7541
§4.1). The list-size guard is raised to 1 MiB so 23 KB SLH-DSA tokens are
measurable; the dynamic table is left at its default.

**Table-size sweep (E6).** Same encoder setup as E5 (NEVER_SENSITIVE), sweeping
the dynamic table over 4/8/16/32/64 KiB. The resize is applied before the first
header block, so request 1 includes the dynamic-table-size-update bytes; requests
2-3 collapsing to ~1 byte proves indexing engaged at that size. Reported per
combination: steady-state bytes, wire bytes saved per request vs the 4 KiB
default, and `payback_requests` = table size / per-request saving. The advertised
table size is decoder memory a server commits *per connection*; fleet cost is
that times concurrent connections, which the write-up states rather than models.

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

- The SLH-DSA JOSE `alg` identifiers are **drafts**; names may change before RFC
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
- The SLH-DSA COSE `alg` identifiers are provisional placeholders (the ML-DSA ones
  are the RFC 9964 registrations); any final registry value of similar magnitude
  encodes in the same 1-2 bytes.
- Netty's HPACK encoder skips Huffman for values shorter than 512 bytes (a CPU
  optimization, `huffCodeThreshold`); the two small classical tokens affected are
  reported as-is and footnoted. Browsers and nghttp2 Huffman-encode regardless, so
  the ~19-20% figure is the transferable Huffman effect.
- HPACK results transfer qualitatively to HTTP/3's QPACK (RFC 9204): same static
  Huffman table, same default dynamic-table economics.

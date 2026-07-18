package org.pqjose.e4;

import com.upokecenter.cbor.CBORObject;
import org.pqjose.core.Csv;
import org.pqjose.core.Keys;
import org.pqjose.core.Providers;
import org.pqjose.core.SigAlg;
import org.pqjose.cose.CoseSign1;
import org.pqjose.cose.CwtClaims;
import org.pqjose.jose.CompactJws;
import org.pqjose.profiles.ClaimProfiles;

import java.nio.file.Path;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * E4: does CWT/COSE_Sign1 (RFC 8392 / RFC 9052) recover the base64url tax that JOSE
 * pays on post-quantum signatures — and how much of the advantage survives when the
 * CWT itself has to ride an HTTP header (where binary must be re-base64url'd)?
 *
 * Same keys, same claim content, same kid, signed both ways; sizes compared:
 *   - binary COSE_Sign1 vs ASCII compact JWS (the fair binary-transport comparison,
 *     e.g. CoAP/OSCORE, MQTT, gRPC binary metadata, protocol buffers)
 *   - base64url(COSE_Sign1) vs compact JWS (the HTTP-header reality)
 */
public final class CoseExperiment {

    private CoseExperiment() {}

    public static void run(Path resultsDir) throws Exception {
        Providers.install();
        List<String> rows = new ArrayList<>();
        System.out.printf("%n%-20s %-18s %8s %8s %7s %10s %7s%n",
                "alg", "profile", "jws_B", "cose_B", "save%", "coseB64_B", "save%");

        for (SigAlg alg : SigAlg.values()) {
            List<String> providers = alg.availableProviders();
            if (providers.isEmpty()) {
                continue;
            }
            String provider = providers.contains(Providers.BC) ? Providers.BC : providers.get(0);
            KeyPair kp = alg.generateKeyPair(provider);
            String kid = Keys.kid(kp.getPublic());
            // COSE kid is a bstr: same 8 SPKI-digest bytes the JOSE kid base64url-encodes
            byte[] kidBytes = java.util.Arrays.copyOf(
                    java.security.MessageDigest.getInstance("SHA-256")
                            .digest(kp.getPublic().getEncoded()), 8);

            for (Map.Entry<String, Map<String, Object>> profile : ClaimProfiles.all().entrySet()) {
                // JOSE side: kid-variant compact JWS (same construction as E1/E2)
                Map<String, Object> header = new LinkedHashMap<>();
                header.put("typ", profile.getKey().equals("oidc-id-token") ? "JWT" : "at+jwt");
                header.put("alg", alg.joseName);
                header.put("kid", kid);
                CompactJws.Token jws = CompactJws.sign(alg, provider, kp.getPrivate(), header, profile.getValue());

                // COSE side: CWT claims map, COSE_Sign1 with alg protected + kid unprotected
                CBORObject claims = CwtClaims.fromJwtClaims(profile.getValue());
                CoseSign1.Signed cose = CoseSign1.sign(alg, provider, kp.getPrivate(), kidBytes, claims);
                if (!CoseSign1.verify(alg, provider, kp.getPublic(), cose.encoded())) {
                    throw new IllegalStateException("COSE verification failed: " + alg.joseName);
                }

                int jwsBytes = jws.totalBytes();
                int coseBytes = cose.encoded().length;
                int coseB64Bytes = Keys.b64url(cose.encoded()).length();
                double saveBinary = 100.0 * (jwsBytes - coseBytes) / jwsBytes;
                double saveHeader = 100.0 * (jwsBytes - coseB64Bytes) / jwsBytes;

                rows.add(String.join(",",
                        alg.joseName, alg.family.name(), profile.getKey(),
                        String.valueOf(jwsBytes), String.valueOf(coseBytes),
                        String.valueOf(cose.protectedLen()), String.valueOf(cose.payloadLen()),
                        String.valueOf(cose.sigLen()), String.valueOf(coseB64Bytes),
                        String.format("%.1f", saveBinary), String.format("%.1f", saveHeader),
                        String.valueOf(coseBytes <= 4096), String.valueOf(coseB64Bytes + 15 <= 4096)));

                System.out.printf("%-20s %-18s %8d %8d %6.1f%% %10d %6.1f%%%n",
                        alg.joseName, profile.getKey(), jwsBytes, coseBytes, saveBinary,
                        coseB64Bytes, saveHeader);
            }
        }

        Csv.write(resultsDir.resolve("cose-vs-jose.csv"),
                "alg,family,profile,jws_bytes,cose_bytes,cose_protected_bytes,cose_payload_bytes,"
                        + "cose_sig_bytes,cose_b64url_bytes,savings_binary_pct,savings_in_header_pct,"
                        + "cose_fits_cookie_4096,cose_b64_fits_cookie_4096",
                rows);
    }
}

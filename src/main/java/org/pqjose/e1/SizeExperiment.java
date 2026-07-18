package org.pqjose.e1;

import org.pqjose.core.Csv;
import org.pqjose.core.Keys;
import org.pqjose.core.Providers;
import org.pqjose.core.SigAlg;
import org.pqjose.core.X5c;
import org.pqjose.jose.CompactJws;
import org.pqjose.jose.Jwks;
import org.pqjose.profiles.ClaimProfiles;

import java.nio.file.Path;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * E1: compact-JWS size per algorithm x claim profile x header variant, measured
 * against documented transport limits.
 *
 * Limits checked (bytes):
 *   4096  – RFC 6265 minimum per-cookie capacity; the de-facto browser cap on name+value.
 *   8192  – nginx large_client_header_buffers default (one header line must fit one buffer);
 *           also the default header ceiling of Tomcat/Jetty/Netty (E2 verifies empirically).
 *   8190  – Apache httpd LimitRequestFieldSize default.
 *   10240 – AWS API Gateway documented combined-header limit.
 */
public final class SizeExperiment {

    private static final String BEARER_PREFIX = "Authorization: Bearer ";
    private static final String COOKIE_PREFIX = "__Host-session=";

    private SizeExperiment() {}

    public static void run(Path resultsDir) throws Exception {
        Providers.install();
        List<String> rows = new ArrayList<>();
        List<String> matrixRows = new ArrayList<>();
        StringBuilder summary = new StringBuilder();
        summary.append(String.format("%-20s %-18s %-8s %8s %8s %8s  %s%n",
                "alg", "profile", "variant", "sig_b", "token_b", "bearer", "fits(cookie/8k/apigw)"));

        for (SigAlg alg : SigAlg.values()) {
            List<String> providers = alg.availableProviders();
            matrixRows.add(alg.joseName + "," + alg.family + "," + String.join("|", providers));
            if (providers.isEmpty()) {
                System.out.println("SKIP " + alg.joseName + ": no provider on this JVM");
                continue;
            }
            String provider = providers.contains(Providers.BC) ? Providers.BC : providers.get(0);
            KeyPair kp = alg.generateKeyPair(provider);
            String kid = Keys.kid(kp.getPublic());
            byte[] rawPub = Keys.rawPublicKey(kp.getPublic());
            Map<String, Object> jwk = Jwks.publicJwk(alg, kp.getPublic(), kid);
            int jwksEntryBytes = CompactJws.toJson(jwk).getBytes(java.nio.charset.StandardCharsets.UTF_8).length;

            byte[] cert = null;
            try {
                cert = X5c.selfSigned(alg, kp);
            } catch (Exception e) {
                System.out.println("x5c unavailable for " + alg.joseName + ": " + e.getMessage());
            }

            for (Map.Entry<String, Map<String, Object>> profile : ClaimProfiles.all().entrySet()) {
                List<String> variants = new ArrayList<>(List.of("kid", "jwk"));
                if (cert != null) {
                    variants.add("x5c");
                }
                for (String variant : variants) {
                    Map<String, Object> header = header(alg, profile.getKey(), variant, kid, jwk, cert);
                    CompactJws.Token token = CompactJws.sign(alg, provider, kp.getPrivate(), header, profile.getValue());
                    if (!CompactJws.verify(alg, provider, kp.getPublic(), token.compact())) {
                        throw new IllegalStateException("verification failed: " + alg.joseName);
                    }

                    int tokenBytes = token.totalBytes();
                    int bearerBytes = BEARER_PREFIX.length() + tokenBytes;
                    int cookieBytes = COOKIE_PREFIX.length() + tokenBytes;
                    boolean fitsCookie = cookieBytes <= 4096;
                    boolean fitsNginx = bearerBytes + 2 <= 8192;   // +CRLF: line must fit one 8k buffer
                    boolean fitsApache = bearerBytes <= 8190;
                    boolean fitsApigw = bearerBytes <= 10240;

                    rows.add(String.join(",",
                            alg.joseName, alg.family.name(), provider, profile.getKey(), variant,
                            String.valueOf(token.rawSigBytes()), String.valueOf(rawPub.length),
                            String.valueOf(token.headerB64()), String.valueOf(token.payloadB64()),
                            String.valueOf(token.sigB64()), String.valueOf(tokenBytes),
                            String.valueOf(bearerBytes), String.valueOf(cookieBytes),
                            String.valueOf(jwksEntryBytes),
                            String.valueOf(fitsCookie), String.valueOf(fitsNginx),
                            String.valueOf(fitsApache), String.valueOf(fitsApigw)));

                    summary.append(String.format("%-20s %-18s %-8s %8d %8d %8d  %s/%s/%s%n",
                            alg.joseName, profile.getKey(), variant,
                            token.rawSigBytes(), tokenBytes, bearerBytes,
                            yn(fitsCookie), yn(fitsNginx), yn(fitsApigw)));
                }
            }
        }

        Csv.write(resultsDir.resolve("token-sizes.csv"),
                "alg,family,provider,profile,header_variant,raw_sig_bytes,raw_pub_bytes,"
                        + "header_b64,payload_b64,sig_b64,token_bytes,bearer_header_bytes,"
                        + "cookie_pair_bytes,jwks_entry_bytes,"
                        + "fits_cookie_4096,fits_nginx_8k,fits_apache_8190,fits_apigw_10240",
                rows);
        Csv.write(resultsDir.resolve("provider-matrix.csv"), "alg,family,providers", matrixRows);
        System.out.println();
        System.out.print(summary);
    }

    private static Map<String, Object> header(SigAlg alg, String profileName, String variant,
                                              String kid, Map<String, Object> jwk, byte[] cert) {
        Map<String, Object> header = new LinkedHashMap<>();
        header.put("typ", profileName.equals("oidc-id-token") ? "JWT" : "at+jwt");
        header.put("alg", alg.joseName);
        switch (variant) {
            case "kid" -> header.put("kid", kid);
            case "jwk" -> header.put("jwk", jwk);
            // x5c uses standard base64 (not base64url) per RFC 7515 section 4.1.6
            case "x5c" -> {
                header.put("kid", kid);
                header.put("x5c", List.of(Base64.getEncoder().encodeToString(cert)));
            }
            default -> throw new IllegalArgumentException(variant);
        }
        return header;
    }

    private static String yn(boolean b) {
        return b ? "y" : "N";
    }
}

package org.pqjose.e3;

import org.pqjose.core.Csv;
import org.pqjose.core.Keys;
import org.pqjose.core.Providers;
import org.pqjose.core.SigAlg;
import org.pqjose.jose.CompactJws;
import org.pqjose.profiles.ClaimProfiles;

import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * E3: per-token sign/verify latency for each algorithm on every JCA provider that
 * offers it (BouncyCastle vs the JDK built-ins). The timed operation is the full
 * per-request path an authorization server pays: Signature.getInstance + init +
 * update + sign/verify over the OIDC ID-token signing input.
 *
 * Adaptive iteration count: up to 3 s or 200 iterations per (alg, provider, op),
 * minimum 10, after 10 warmup iterations — SLH-DSA signing is slow enough that a
 * fixed high count would run for minutes.
 */
public final class SpeedBench {

    private SpeedBench() {}

    public static void run(Path resultsDir) throws Exception {
        Providers.install();
        List<String> rows = new ArrayList<>();

        for (SigAlg alg : SigAlg.values()) {
            for (String provider : alg.availableProviders()) {
                KeyPair kp = keyPairFor(alg, provider);
                if (kp == null) {
                    System.out.println("SKIP bench " + alg.joseName + " on " + provider
                            + ": no usable key path");
                    continue;
                }
                byte[] signingInput = signingInput(alg);
                byte[] sig = signOnce(alg, provider, kp.getPrivate(), signingInput);

                long[] signNs = time(() -> signOnce(alg, provider, kp.getPrivate(), signingInput));
                long[] verifyNs = time(() -> verifyOnce(alg, provider, kp.getPublic(), signingInput, sig));

                rows.add(row(alg, provider, "sign", signNs));
                rows.add(row(alg, provider, "verify", verifyNs));
                System.out.printf("%-20s %-12s sign %9.1f us  verify %9.1f us  (n=%d/%d)%n",
                        alg.joseName, provider, median(signNs) / 1e3, median(verifyNs) / 1e3,
                        signNs.length, verifyNs.length);
            }
        }

        Csv.write(resultsDir.resolve("sign-verify-bench.csv"),
                "alg,provider,op,iters,median_us,p10_us,p90_us", rows);
    }

    /** Keys native to the provider; falls back to importing BC-generated keys via KeyFactory. */
    private static KeyPair keyPairFor(SigAlg alg, String provider) {
        try {
            return alg.generateKeyPair(provider);
        } catch (Exception genFailed) {
            try {
                KeyPair bc = alg.generateKeyPair(Providers.BC);
                KeyFactory kf = keyFactoryFor(alg, provider);
                PublicKey pub = kf.generatePublic(new X509EncodedKeySpec(bc.getPublic().getEncoded()));
                PrivateKey priv = kf.generatePrivate(new PKCS8EncodedKeySpec(bc.getPrivate().getEncoded()));
                return new KeyPair(pub, priv);
            } catch (Exception importFailed) {
                return null;
            }
        }
    }

    private static KeyFactory keyFactoryFor(SigAlg alg, String provider) throws Exception {
        Exception last = null;
        for (String name : keyFactoryNames(alg)) {
            try {
                return KeyFactory.getInstance(name, provider);
            } catch (Exception e) {
                last = e;
            }
        }
        throw last;
    }

    private static List<String> keyFactoryNames(SigAlg alg) {
        return switch (alg) {
            case RS256 -> List.of("RSA");
            case ES256 -> List.of("EC");
            case ED25519 -> List.of("Ed25519", "EdDSA");
            default -> List.of(alg.joseName, alg.joseName.startsWith("ML-DSA") ? "ML-DSA" : "SLH-DSA");
        };
    }

    private static byte[] signingInput(SigAlg alg) {
        Map<String, Object> header = new LinkedHashMap<>();
        header.put("typ", "JWT");
        header.put("alg", alg.joseName);
        header.put("kid", "bench-key");
        String h = Keys.b64url(CompactJws.toJson(header).getBytes(java.nio.charset.StandardCharsets.UTF_8));
        String p = Keys.b64url(CompactJws.toJson(ClaimProfiles.oidcIdToken())
                .getBytes(java.nio.charset.StandardCharsets.UTF_8));
        return Keys.ascii(h + "." + p);
    }

    private static byte[] signOnce(SigAlg alg, String provider, PrivateKey priv, byte[] input) {
        try {
            Signature s = alg.newSignature(provider);
            s.initSign(priv);
            s.update(input);
            return s.sign();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static void verifyOnce(SigAlg alg, String provider, PublicKey pub, byte[] input, byte[] sig) {
        try {
            Signature s = alg.newSignature(provider);
            s.initVerify(pub);
            s.update(input);
            if (!s.verify(sig)) {
                throw new IllegalStateException("verify=false during bench");
            }
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private interface Op {
        void run();
    }

    private static long[] time(Op op) {
        for (int i = 0; i < 10; i++) {
            op.run();
        }
        List<Long> samples = new ArrayList<>();
        long budget = System.nanoTime() + 3_000_000_000L;
        while ((samples.size() < 200 && System.nanoTime() < budget) || samples.size() < 10) {
            long t0 = System.nanoTime();
            op.run();
            samples.add(System.nanoTime() - t0);
        }
        long[] out = samples.stream().mapToLong(Long::longValue).toArray();
        Arrays.sort(out);
        return out;
    }

    private static long median(long[] sorted) {
        return sorted[sorted.length / 2];
    }

    private static String row(SigAlg alg, String provider, String op, long[] sorted) {
        return String.join(",", alg.joseName, provider, op,
                String.valueOf(sorted.length),
                String.format("%.1f", sorted[sorted.length / 2] / 1e3),
                String.format("%.1f", sorted[(int) (sorted.length * 0.10)] / 1e3),
                String.format("%.1f", sorted[(int) (sorted.length * 0.90)] / 1e3));
    }
}

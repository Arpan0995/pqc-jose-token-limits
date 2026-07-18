package org.pqjose.e2;

import org.pqjose.core.Csv;
import org.pqjose.core.Keys;
import org.pqjose.core.Providers;
import org.pqjose.core.SigAlg;
import org.pqjose.e2.servers.JettyTarget;
import org.pqjose.e2.servers.NettyTarget;
import org.pqjose.e2.servers.TomcatTarget;
import org.pqjose.e2.servers.UndertowTarget;
import org.pqjose.jose.CompactJws;
import org.pqjose.profiles.ClaimProfiles;

import java.nio.file.Path;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * E2: drive real PQ-signed bearer tokens through four embedded Java HTTP servers at
 * default configuration and record accept/reject, then binary-search each server's
 * empirical token-size ceiling with synthetic tokens.
 */
public final class ServerDefaultsExperiment {

    private record TokenCase(String alg, String profile, String token) {}

    private ServerDefaultsExperiment() {}

    public static void run(Path resultsDir) throws Exception {
        Providers.install();
        List<TokenCase> cases = buildTokens();
        List<String> rows = new ArrayList<>();
        List<ServerTarget> targets = List.of(
                new JettyTarget(), new TomcatTarget(), new UndertowTarget(), new NettyTarget());

        for (ServerTarget target : targets) {
            int port = target.start();
            waitReady(port);
            System.out.printf("%n%s %s on :%d%n", target.name(), target.version(), port);

            for (TokenCase tc : cases) {
                String result = HttpProbe.get(port, tc.token());
                boolean accepted = "200".equals(result);
                rows.add(String.join(",", target.name(), target.version(), tc.alg(), tc.profile(),
                        String.valueOf(tc.token().length()),
                        String.valueOf("Authorization: Bearer ".length() + tc.token().length()),
                        result, String.valueOf(accepted)));
                System.out.printf("  %-20s %-18s %7d B -> %s%n",
                        tc.alg(), tc.profile(), tc.token().length(), result);
            }

            long ceiling = ceiling(port);
            rows.add(String.join(",", target.name(), target.version(), "SYNTHETIC-CEILING", "-",
                    String.valueOf(ceiling), String.valueOf("Authorization: Bearer ".length() + ceiling),
                    "max_accepted_token_bytes", "-"));
            System.out.printf("  empirical ceiling: %d-byte token still accepted%n", ceiling);
            target.close();
        }

        Csv.write(resultsDir.resolve("server-defaults.csv"),
                "server,server_version,alg,profile,token_bytes,bearer_header_bytes,result,accepted",
                rows);
    }

    private static List<TokenCase> buildTokens() throws Exception {
        List<TokenCase> cases = new ArrayList<>();
        for (SigAlg alg : SigAlg.values()) {
            List<String> providers = alg.availableProviders();
            if (providers.isEmpty()) {
                continue;
            }
            String provider = providers.contains(Providers.BC) ? Providers.BC : providers.get(0);
            KeyPair kp = alg.generateKeyPair(provider);
            String kid = Keys.kid(kp.getPublic());
            for (Map.Entry<String, Map<String, Object>> profile : ClaimProfiles.all().entrySet()) {
                Map<String, Object> header = new LinkedHashMap<>();
                header.put("typ", profile.getKey().equals("oidc-id-token") ? "JWT" : "at+jwt");
                header.put("alg", alg.joseName);
                header.put("kid", kid);
                CompactJws.Token t = CompactJws.sign(alg, provider, kp.getPrivate(), header, profile.getValue());
                cases.add(new TokenCase(alg.joseName, profile.getKey(), t.compact()));
            }
        }
        return cases;
    }

    /** Largest synthetic token (in bytes) the server still answers 200 for, up to 2 MiB. */
    private static long ceiling(int port) {
        long lo = 64;
        long hi = 2 * 1024 * 1024;
        if (!HttpProbe.accepted(port, "A".repeat((int) lo))) {
            return 0;
        }
        if (HttpProbe.accepted(port, "A".repeat((int) hi))) {
            return hi;   // beyond the tested range
        }
        while (hi - lo > 1) {
            long mid = (lo + hi) / 2;
            if (HttpProbe.accepted(port, "A".repeat((int) mid))) {
                lo = mid;
            } else {
                hi = mid;
            }
        }
        return lo;
    }

    private static void waitReady(int port) throws InterruptedException {
        for (int i = 0; i < 50; i++) {
            if (HttpProbe.accepted(port, "warmup")) {
                return;
            }
            Thread.sleep(100);
        }
        throw new IllegalStateException("server on :" + port + " never became ready");
    }
}

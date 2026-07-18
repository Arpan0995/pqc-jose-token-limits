package org.pqjose.e2;

import org.pqjose.core.Csv;
import org.pqjose.core.Providers;
import org.pqjose.e2.servers.JettyTarget;
import org.pqjose.e2.servers.NettyTarget;
import org.pqjose.e2.servers.TomcatTarget;
import org.pqjose.e2.servers.UndertowTarget;
import org.pqjose.jose.TokenFactory;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * E2: drive real PQ-signed bearer tokens through four embedded Java HTTP servers at
 * default configuration and record accept/reject, then binary-search each server's
 * empirical token-size ceiling with synthetic tokens.
 */
public final class ServerDefaultsExperiment {

    private ServerDefaultsExperiment() {}

    public static void run(Path resultsDir) throws Exception {
        Providers.install();
        List<TokenFactory.TokenCase> cases = TokenFactory.kidTokens();
        List<String> rows = new ArrayList<>();
        List<ServerTarget> targets = List.of(
                new JettyTarget(), new TomcatTarget(), new UndertowTarget(), new NettyTarget());

        for (ServerTarget target : targets) {
            int port = target.start();
            waitReady(port);
            System.out.printf("%n%s %s on :%d%n", target.name(), target.version(), port);

            for (TokenFactory.TokenCase tc : cases) {
                String result = HttpProbe.get(port, tc.token());
                boolean accepted = "200".equals(result);
                rows.add(String.join(",", target.name(), target.version(), tc.alg().joseName,
                        tc.profile(), String.valueOf(tc.token().length()),
                        String.valueOf("Authorization: Bearer ".length() + tc.token().length()),
                        result, String.valueOf(accepted)));
                System.out.printf("  %-20s %-18s %7d B -> %s%n",
                        tc.alg().joseName, tc.profile(), tc.token().length(), result);
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

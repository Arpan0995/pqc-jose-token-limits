package org.pqjose;

import org.pqjose.core.Providers;
import org.pqjose.e1.SizeExperiment;
import org.pqjose.e2.ServerDefaultsExperiment;
import org.pqjose.e3.SpeedBench;
import org.pqjose.e4.CoseExperiment;
import org.pqjose.e5.HpackExperiment;
import org.pqjose.e6.TableSweepExperiment;

import java.nio.file.Path;

/** Entry point: runs the experiments and writes CSVs into results/. */
public final class Harness {

    private Harness() {}

    public static void main(String[] args) throws Exception {
        Providers.install();
        String cmd = args.length > 0 ? args[0] : "all";
        Path results = Path.of(args.length > 1 ? args[1] : "results");
        switch (cmd) {
            case "sizes" -> SizeExperiment.run(results);
            case "servers" -> ServerDefaultsExperiment.run(results);
            case "bench" -> SpeedBench.run(results);
            case "cose" -> CoseExperiment.run(results);
            case "hpack" -> HpackExperiment.run(results);
            case "tablesweep" -> TableSweepExperiment.run(results);
            case "all" -> {
                SizeExperiment.run(results);
                ServerDefaultsExperiment.run(results);
                SpeedBench.run(results);
                CoseExperiment.run(results);
                HpackExperiment.run(results);
                TableSweepExperiment.run(results);
            }
            default -> {
                System.err.println("usage: Harness [sizes|servers|bench|cose|hpack|tablesweep|all] [resultsDir]");
                System.exit(2);
            }
        }
    }
}

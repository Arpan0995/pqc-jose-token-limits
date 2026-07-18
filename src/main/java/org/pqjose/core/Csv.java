package org.pqjose.core;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/** Minimal CSV writer; all values in this project are comma-free by construction. */
public final class Csv {

    private Csv() {}

    public static void write(Path file, String header, List<String> rows) throws IOException {
        List<String> lines = new ArrayList<>(rows.size() + 1);
        lines.add(header);
        lines.addAll(rows);
        Files.createDirectories(file.getParent());
        Files.write(file, lines);
        System.out.println("wrote " + file + " (" + rows.size() + " rows)");
    }
}

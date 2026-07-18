package org.pqjose.e6;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.handler.codec.http2.DefaultHttp2Headers;
import io.netty.handler.codec.http2.DefaultHttp2HeadersEncoder;
import io.netty.handler.codec.http2.Http2Headers;
import io.netty.handler.codec.http2.Http2HeadersEncoder;
import org.pqjose.core.Csv;
import org.pqjose.jose.TokenFactory;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * E6: what does raising SETTINGS_HEADER_TABLE_SIZE buy back for PQ bearer tokens?
 *
 * E5 showed that any token whose HPACK entry (name + value + 32, RFC 7541 section
 * 4.1) exceeds the default 4,096-byte dynamic table can never be indexed and
 * re-pays the full Huffman'd literal on every request. The advertised table size
 * is also the per-connection decoder memory a server commits, so the operator
 * question is a trade: table bytes per connection vs literal bytes per request.
 *
 * Sweep: 4 KiB (default), 8, 16, 32, 64 KiB. For each (token, table size), a
 * fresh encoder resized before the first header block (the resize itself costs a
 * few bytes of dynamic-table-size-update in request 1, which is included), then
 * three encodings: request 2/3 collapsing to a few bytes proves indexing engaged.
 * `payback_requests` = table size / steady-state saving — how many requests on a
 * connection until the extra memory has paid for itself in wire bytes.
 */
public final class TableSweepExperiment {

    private static final int[] TABLE_SIZES = {4096, 8192, 16384, 32768, 65536};
    private static final int HPACK_ENTRY_OVERHEAD = 32;

    private TableSweepExperiment() {}

    public static void run(Path resultsDir) throws Exception {
        List<String> rows = new ArrayList<>();
        System.out.printf("%n%-20s %-18s %7s | smallest table that indexes -> steady-state cost%n",
                "alg", "profile", "entry_B");

        for (TokenFactory.TokenCase tc : TokenFactory.kidTokens()) {
            String value = "Bearer " + tc.token();
            int entrySize = "authorization".length() + value.length() + HPACK_ENTRY_OVERHEAD;

            long defaultSteady = -1;
            long minIndexingTable = -1;
            long steadyAtMin = -1;

            for (int table : TABLE_SIZES) {
                long[] sizes = encode(value, table, 3);
                boolean indexed = sizes[1] <= 8;
                long steady = sizes[1];
                if (table == 4096) {
                    defaultSteady = steady;
                }
                if (indexed && minIndexingTable < 0) {
                    minIndexingTable = table;
                    steadyAtMin = steady;
                }
                long savedPerReq = indexed ? defaultSteady - steady : 0;
                String payback = indexed && savedPerReq > 0
                        ? String.valueOf((long) Math.ceil((double) table / savedPerReq))
                        : "-";
                rows.add(String.join(",",
                        tc.alg().joseName, tc.profile(), String.valueOf(value.length()),
                        String.valueOf(entrySize), String.valueOf(table),
                        String.valueOf(sizes[0]), String.valueOf(sizes[1]), String.valueOf(sizes[2]),
                        String.valueOf(indexed), String.valueOf(savedPerReq), payback));
            }

            System.out.printf("%-20s %-18s %7d | %s%n",
                    tc.alg().joseName, tc.profile(), entrySize,
                    minIndexingTable < 0
                            ? "not indexable up to 64 KiB"
                            : String.format("%d KiB -> %d B/req (saves %d B/req vs default's %d)",
                                    minIndexingTable / 1024, steadyAtMin,
                                    defaultSteady - steadyAtMin, defaultSteady));
        }

        Csv.write(resultsDir.resolve("hpack-table-sweep.csv"),
                "alg,profile,value_bytes,hpack_entry_bytes,table_size,req1_bytes,req2_bytes,"
                        + "req3_bytes,indexed,wire_saved_per_request,payback_requests",
                rows);
    }

    private static long[] encode(String value, int tableSize, int requests) throws Exception {
        DefaultHttp2HeadersEncoder encoder =
                new DefaultHttp2HeadersEncoder(Http2HeadersEncoder.NEVER_SENSITIVE);
        encoder.maxHeaderListSize(1 << 20);
        encoder.maxHeaderTableSize(tableSize);
        long[] sizes = new long[requests];
        for (int i = 0; i < requests; i++) {
            Http2Headers headers = new DefaultHttp2Headers().add("authorization", value);
            ByteBuf buf = Unpooled.buffer();
            try {
                encoder.encodeHeaders(1, headers, buf);
                sizes[i] = buf.readableBytes();
            } finally {
                buf.release();
            }
        }
        return sizes;
    }
}

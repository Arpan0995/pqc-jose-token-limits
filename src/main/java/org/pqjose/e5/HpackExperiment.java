package org.pqjose.e5;

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
 * E5: what does HTTP/2 HPACK (RFC 7541) actually do for PQ bearer tokens?
 *
 * Two mechanisms are measured separately with Netty's encoder at the RFC-default
 * 4096-byte dynamic table:
 *
 *   1. Huffman coding (sensitivity=ALWAYS -> never-indexed literal): how much of
 *      the base64url signature's 33% expansion does the static Huffman table claw
 *      back on a first/every transmission?
 *   2. Dynamic-table indexing (sensitivity=NEVER -> indexable): an entry costs
 *      name+value+32 bytes of table space; a token whose entry exceeds 4096 can
 *      never be indexed, so *every* request pays the full literal cost. Requests
 *      2 and 3 reveal whether indexing engaged (a handful of bytes) or not.
 *
 * The authorization header is encoded alone so byte counts isolate the token.
 */
public final class HpackExperiment {

    private static final int RFC7541_DEFAULT_TABLE = 4096;
    private static final int HPACK_ENTRY_OVERHEAD = 32;

    private HpackExperiment() {}

    public static void run(Path resultsDir) throws Exception {
        List<String> rows = new ArrayList<>();
        System.out.printf("%n%-20s %-18s %7s %9s %7s %9s %9s %10s%n",
                "alg", "profile", "value_B", "huffman_B", "save%", "req2_B", "req3_B", "indexable");

        for (TokenFactory.TokenCase tc : TokenFactory.kidTokens()) {
            String value = "Bearer " + tc.token();
            int entrySize = "authorization".length() + value.length() + HPACK_ENTRY_OVERHEAD;
            boolean indexable = entrySize <= RFC7541_DEFAULT_TABLE;

            // Huffman-only path: never-indexed literal on every request
            long huffman = encode(Http2HeadersEncoder.ALWAYS_SENSITIVE, value, 1)[0];
            double save = 100.0 * (value.length() - huffman) / value.length();

            // Indexing path: same encoder across three requests
            long[] indexed = encode(Http2HeadersEncoder.NEVER_SENSITIVE, value, 3);

            rows.add(String.join(",",
                    tc.alg().joseName, tc.profile(),
                    String.valueOf(value.length()), String.valueOf(entrySize),
                    String.valueOf(huffman), String.format("%.1f", save),
                    String.valueOf(indexed[0]), String.valueOf(indexed[1]), String.valueOf(indexed[2]),
                    String.valueOf(indexable)));

            System.out.printf("%-20s %-18s %7d %9d %6.1f%% %9d %9d %10s%n",
                    tc.alg().joseName, tc.profile(), value.length(), huffman, save,
                    indexed[1], indexed[2], indexable ? "yes" : "NO");
        }

        Csv.write(resultsDir.resolve("hpack.csv"),
                "alg,profile,value_bytes,hpack_entry_bytes,huffman_encoded_bytes,huffman_savings_pct,"
                        + "req1_bytes,req2_bytes,req3_bytes,indexable_at_default_table",
                rows);
    }

    /** Encoded header-block sizes for `requests` consecutive encodings on one encoder. */
    private static long[] encode(Http2HeadersEncoder.SensitivityDetector sensitivity,
                                 String value, int requests) throws Exception {
        DefaultHttp2HeadersEncoder encoder = new DefaultHttp2HeadersEncoder(sensitivity);
        // Raise the list-size guard so 23 KB SLH-DSA tokens are measurable; the
        // dynamic table stays at the RFC 7541 default of 4096.
        encoder.maxHeaderListSize(1 << 20);
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

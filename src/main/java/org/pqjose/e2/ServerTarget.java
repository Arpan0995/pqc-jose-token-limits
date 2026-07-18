package org.pqjose.e2;

/** An embedded HTTP server started with DEFAULT configuration — no limit is touched. */
public interface ServerTarget extends AutoCloseable {

    String name();

    String version();

    /** Starts the server on an ephemeral port and returns it. */
    int start() throws Exception;

    @Override
    void close() throws Exception;
}

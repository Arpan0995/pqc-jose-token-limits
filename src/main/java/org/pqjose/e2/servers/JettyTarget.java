package org.pqjose.e2.servers;

import org.eclipse.jetty.server.Handler;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.Response;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.util.Callback;
import org.pqjose.e2.ServerTarget;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

/** Jetty 12 with an out-of-the-box HttpConfiguration (requestHeaderSize default 8 KiB). */
public final class JettyTarget implements ServerTarget {

    private Server server;
    private ServerConnector connector;

    @Override
    public String name() {
        return "jetty";
    }

    @Override
    public String version() {
        return Server.getVersion();
    }

    @Override
    public int start() throws Exception {
        server = new Server();
        connector = new ServerConnector(server);
        connector.setPort(0);
        server.addConnector(connector);
        server.setHandler(new Handler.Abstract() {
            @Override
            public boolean handle(Request request, Response response, Callback callback) {
                response.setStatus(200);
                response.write(true, ByteBuffer.wrap("ok".getBytes(StandardCharsets.US_ASCII)), callback);
                return true;
            }
        });
        server.start();
        return connector.getLocalPort();
    }

    @Override
    public void close() throws Exception {
        server.stop();
    }
}

package org.pqjose.e2.servers;

import io.undertow.Undertow;
import io.undertow.Version;
import org.pqjose.e2.ServerTarget;

import java.net.InetSocketAddress;

/** Undertow 2.3 with builder defaults (MAX_HEADER_SIZE default 1 MiB). */
public final class UndertowTarget implements ServerTarget {

    private Undertow undertow;

    @Override
    public String name() {
        return "undertow";
    }

    @Override
    public String version() {
        return Version.getVersionString();
    }

    @Override
    public int start() {
        undertow = Undertow.builder()
                .addHttpListener(0, "127.0.0.1")
                .setHandler(exchange -> {
                    exchange.setStatusCode(200);
                    exchange.getResponseSender().send("ok");
                })
                .build();
        undertow.start();
        InetSocketAddress addr = (InetSocketAddress) undertow.getListenerInfo().get(0).getAddress();
        return addr.getPort();
    }

    @Override
    public void close() {
        undertow.stop();
    }
}

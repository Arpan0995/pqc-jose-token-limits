package org.pqjose.e2.servers;

import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.catalina.Context;
import org.apache.catalina.startup.Tomcat;
import org.apache.catalina.util.ServerInfo;
import org.pqjose.e2.ServerTarget;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/** Embedded Tomcat 10.1 with the default NIO connector (maxHttpRequestHeaderSize default 8 KiB). */
public final class TomcatTarget implements ServerTarget {

    private Tomcat tomcat;

    @Override
    public String name() {
        return "tomcat";
    }

    @Override
    public String version() {
        return ServerInfo.getServerNumber();
    }

    @Override
    public int start() throws Exception {
        Path base = Files.createTempDirectory("tomcat-e2");
        tomcat = new Tomcat();
        tomcat.setBaseDir(base.toString());
        tomcat.setPort(0);
        tomcat.getConnector();   // materialize the default connector
        Context ctx = tomcat.addContext("", base.toString());
        Tomcat.addServlet(ctx, "ok", new HttpServlet() {
            @Override
            protected void service(HttpServletRequest req, HttpServletResponse resp) throws IOException {
                resp.setContentType("text/plain");
                resp.getWriter().write("ok");
            }
        });
        ctx.addServletMappingDecoded("/*", "ok");
        tomcat.start();
        return tomcat.getConnector().getLocalPort();
    }

    @Override
    public void close() throws Exception {
        tomcat.stop();
        tomcat.destroy();
    }
}

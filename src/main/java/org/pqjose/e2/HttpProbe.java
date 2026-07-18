package org.pqjose.e2;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;

/**
 * Raw-socket HTTP/1.1 probe. Deliberately not java.net.http.HttpClient, which imposes
 * its own header limits and would contaminate the measurement of the server's behaviour.
 */
public final class HttpProbe {

    private HttpProbe() {}

    /** Sends GET / with the token as a Bearer header; returns the status code or a failure tag. */
    public static String get(int port, String bearerToken) {
        try (Socket s = new Socket()) {
            s.connect(new InetSocketAddress("127.0.0.1", port), 2000);
            s.setSoTimeout(8000);
            OutputStream out = s.getOutputStream();
            out.write("GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n".getBytes(StandardCharsets.US_ASCII));
            out.write(("Authorization: Bearer " + bearerToken + "\r\n").getBytes(StandardCharsets.US_ASCII));
            out.write("Connection: close\r\n\r\n".getBytes(StandardCharsets.US_ASCII));
            out.flush();
            BufferedReader in = new BufferedReader(
                    new InputStreamReader(s.getInputStream(), StandardCharsets.US_ASCII));
            String statusLine = in.readLine();
            if (statusLine == null) {
                return "CONN_CLOSED";
            }
            String[] parts = statusLine.split(" ");
            return parts.length >= 2 ? parts[1] : "MALFORMED";
        } catch (SocketTimeoutException e) {
            return "TIMEOUT";
        } catch (IOException e) {
            // server reset the connection mid-request (typical for oversized headers)
            return "CONN_RESET";
        }
    }

    public static boolean accepted(int port, String bearerToken) {
        return "200".equals(get(port, bearerToken));
    }
}

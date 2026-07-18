package org.pqjose.e2.servers;

import io.netty.bootstrap.ServerBootstrap;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.handler.codec.http.DefaultFullHttpResponse;
import io.netty.handler.codec.http.FullHttpResponse;
import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpObject;
import io.netty.handler.codec.http.HttpRequest;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.codec.http.HttpServerCodec;
import io.netty.handler.codec.http.HttpVersion;
import org.pqjose.e2.ServerTarget;

import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;

/**
 * Netty 4.1 with a stock HttpServerCodec (maxHeaderSize default 8 KiB). Oversized
 * headers surface as a failed decoderResult, answered here with 431 like the
 * mainstream Netty-based frameworks do.
 */
public final class NettyTarget implements ServerTarget {

    private EventLoopGroup boss;
    private EventLoopGroup worker;
    private io.netty.channel.Channel channel;

    @Override
    public String name() {
        return "netty";
    }

    @Override
    public String version() {
        String v = HttpServerCodec.class.getPackage().getImplementationVersion();
        return v != null ? v : "4.1.x";
    }

    @Override
    public int start() throws Exception {
        boss = new NioEventLoopGroup(1);
        worker = new NioEventLoopGroup(1);
        ServerBootstrap b = new ServerBootstrap();
        b.group(boss, worker)
                .channel(NioServerSocketChannel.class)
                .childHandler(new ChannelInitializer<SocketChannel>() {
                    @Override
                    protected void initChannel(SocketChannel ch) {
                        ch.pipeline().addLast(new HttpServerCodec());
                        ch.pipeline().addLast(new SimpleChannelInboundHandler<HttpObject>() {
                            @Override
                            protected void channelRead0(ChannelHandlerContext ctx, HttpObject msg) {
                                if (!(msg instanceof HttpRequest req)) {
                                    return;
                                }
                                if (req.decoderResult().isFailure()) {
                                    FullHttpResponse resp = new DefaultFullHttpResponse(
                                            HttpVersion.HTTP_1_1,
                                            HttpResponseStatus.REQUEST_HEADER_FIELDS_TOO_LARGE);
                                    resp.headers().set(HttpHeaderNames.CONTENT_LENGTH, 0);
                                    ctx.writeAndFlush(resp).addListener(ChannelFutureListener.CLOSE);
                                } else {
                                    byte[] body = "ok".getBytes(StandardCharsets.US_ASCII);
                                    FullHttpResponse resp = new DefaultFullHttpResponse(
                                            HttpVersion.HTTP_1_1, HttpResponseStatus.OK,
                                            Unpooled.wrappedBuffer(body));
                                    resp.headers().set(HttpHeaderNames.CONTENT_LENGTH, body.length);
                                    ctx.writeAndFlush(resp).addListener(ChannelFutureListener.CLOSE);
                                }
                            }
                        });
                    }
                });
        channel = b.bind("127.0.0.1", 0).sync().channel();
        return ((InetSocketAddress) channel.localAddress()).getPort();
    }

    @Override
    public void close() throws Exception {
        if (channel != null) {
            channel.close().sync();
        }
        boss.shutdownGracefully();
        worker.shutdownGracefully();
    }
}

package net.cakemc.dns.network

import io.netty.bootstrap.Bootstrap
import io.netty.buffer.Unpooled
import io.netty.channel.*
import io.netty.channel.epoll.Epoll
import io.netty.channel.epoll.EpollDatagramChannel
import io.netty.channel.epoll.EpollIoHandler
import io.netty.channel.kqueue.KQueue
import io.netty.channel.kqueue.KQueueDatagramChannel
import io.netty.channel.kqueue.KQueueIoHandler
import io.netty.channel.nio.NioIoHandler
import io.netty.channel.socket.DatagramChannel
import io.netty.channel.socket.DatagramPacket
import io.netty.channel.socket.nio.NioDatagramChannel
import net.cakemc.dns.types.DNSRecordType
import net.cakemc.dns.units.DNSUtils
import net.cakemc.dns.DnsResponse
import java.net.InetSocketAddress

class UDPClient(
    val dnsHost: String = "127.0.0.1",
    val dnsPort: Int = 53
) {

    companion object {
        val EPOLL: Boolean = Epoll.isAvailable()
        val KQUEUE: Boolean = KQueue.isAvailable()
    }

    private val group: EventLoopGroup
    private val channelType: Class<out DatagramChannel>


    init {
        val ioHandlerFactory = when {
            EPOLL && KQUEUE -> KQueueIoHandler.newFactory()
            EPOLL -> EpollIoHandler.newFactory()
            else -> NioIoHandler.newFactory()
        }

        this.group = MultiThreadIoEventLoopGroup(ioHandlerFactory)

        this.channelType = when {
            EPOLL && KQUEUE -> KQueueDatagramChannel::class.java
            EPOLL -> EpollDatagramChannel::class.java
            else -> NioDatagramChannel::class.java
        }
    }

    /**
     * Query a DNS server for the given host and record type.
     *
     * @param host domain name to query
     * @param type DNSRecordType (e.g. A, MX, TXT, etc.)
     * @param serverIp IP address of the DNS server (default 127.0.0.1)
     * @param port DNS server port (default 53 or your dev port)
     */
    fun query(
        host: String,
        type: DNSRecordType,
    ): DnsResponse? {
        val promise = group.next().newPromise<DnsResponse>()

        val bootstrap = Bootstrap()
            .group(group)
            .channel(channelType)
            .option(ChannelOption.SO_BROADCAST, true)
            .handler(object : SimpleChannelInboundHandler<DatagramPacket>() {
                override fun channelRead0(ctx: ChannelHandlerContext, packet: DatagramPacket) {
                    try {
                        val responseBytes = ByteArray(packet.content().readableBytes())
                        packet.content().readBytes(responseBytes)
                        val parsed = DNSUtils.parseDNSResponse(responseBytes)
                        promise.setSuccess(parsed)
                        ctx.close()
                    } catch (e: Exception) {
                        promise.setFailure(e)
                    }
                }

                override fun exceptionCaught(ctx: ChannelHandlerContext, cause: Throwable) {
                    promise.setFailure(cause)
                    ctx.close()
                }
            })

        val channel = bootstrap.bind(0).sync().channel()

        val query = DNSUtils.createDNSQuery(host).toMutableList()

        // Override the record type in the last 4 bytes (QTYPE)
        query[query.size - 4] = 0x00
        query[query.size - 3] = type.code.toByte()

        val queryBytes = query.toByteArray()
        val address = InetSocketAddress(dnsHost, dnsPort)
        val packet = DatagramPacket(Unpooled.copiedBuffer(queryBytes), address)

        channel.writeAndFlush(packet).sync()

        return promise.sync().getNow()
    }

    fun shutdown() {
        group.shutdownGracefully().syncUninterruptibly()
    }
}

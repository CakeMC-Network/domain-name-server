package net.cakemc.dns.network

import io.netty.bootstrap.Bootstrap
import io.netty.channel.*
import io.netty.channel.epoll.Epoll
import io.netty.channel.epoll.EpollDatagramChannel
import io.netty.channel.epoll.EpollIoHandler
import io.netty.channel.kqueue.KQueue
import io.netty.channel.kqueue.KQueueDatagramChannel
import io.netty.channel.kqueue.KQueueIoHandler
import io.netty.channel.nio.NioIoHandler
import io.netty.channel.socket.DatagramChannel
import io.netty.channel.socket.nio.NioDatagramChannel
import net.cakemc.dns.DomainManager

class UDPServer(
    val domainManager: DomainManager,
    val host: String = "0.0.0.0",
    val port: Int = 53
) {

    private var endpoint: Channel? = null

    private val group: EventLoopGroup
    private val channel: Class<out DatagramChannel?>

    companion object {
        val EPOLL: Boolean = Epoll.isAvailable()
        val KQUEUE: Boolean = KQueue.isAvailable()
    }

    init {
        val ioHandlerFactory = when {
            EPOLL && KQUEUE -> KQueueIoHandler.newFactory()
            EPOLL -> EpollIoHandler.newFactory()
            else -> NioIoHandler.newFactory()
        }

        this.group = MultiThreadIoEventLoopGroup(ioHandlerFactory)

        this.channel = when {
            EPOLL && KQUEUE -> KQueueDatagramChannel::class.java
            EPOLL -> EpollDatagramChannel::class.java
            else -> NioDatagramChannel::class.java
        }
    }

    fun start() {
        try {
            val bootstrap = Bootstrap()
                .group(group)
                .channel(channel)
                .option(ChannelOption.SO_BROADCAST, true)
                .handler(DatagramHandler(
                    domainManager
                ))

            endpoint = bootstrap.bind(host, port).sync().channel()

            println("DNS Server is listening on port $host:$port")
            endpoint?.closeFuture()?.sync()
        } finally {
            this.stop()
        }
    }

    fun stop() {
        try {
            endpoint?.close()?.syncUninterruptibly()

            group.shutdownGracefully().syncUninterruptibly()
        } catch (e: Exception) {
            e.printStackTrace()
        } finally {
            group.shutdownGracefully()
        }
    }
}

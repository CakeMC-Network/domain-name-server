package net.cakemc.dns.network

import io.netty.buffer.Unpooled
import io.netty.channel.ChannelHandlerContext
import io.netty.channel.SimpleChannelInboundHandler
import io.netty.channel.socket.DatagramPacket
import net.cakemc.dns.DomainManager
import net.cakemc.dns.units.DNSUtils

class DatagramHandler(
    val domainManager: DomainManager
): SimpleChannelInboundHandler<DatagramPacket>() {

    override fun channelRead0(ctx: ChannelHandlerContext, packet: DatagramPacket) {
        try {
            val queryData = ByteArray(packet.content().readableBytes())
            packet.content().readBytes(queryData)

            println("Received DNS query from ${packet.sender()}")

            val query = DNSUtils.parseDNSQuery(queryData)
            // for debug only
            val responseBytes = domainManager.createResponse(queryData)

            val responsePacket = DatagramPacket(
                Unpooled.copiedBuffer(responseBytes),
                packet.sender()
            )
            ctx.writeAndFlush(responsePacket).addListener {
                println("Sent DNS response to ${packet.sender()}")
            }
        } catch (e: Exception) {
            println("Failed to handle DNS query: ${e.message}")
        }
    }

    @Deprecated("Deprecated in Java")
    override fun exceptionCaught(ctx: ChannelHandlerContext, cause: Throwable) {
        cause.printStackTrace()
        ctx.close()
    }

}
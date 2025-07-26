package net.cakemc.dns

import net.cakemc.dns.network.UDPServer
import net.cakemc.dns.register.DnsRegistry

class DomainNameServer {

    val dnsRegistry: DnsRegistry
    val domainManager: DomainManager
    val udpServer: UDPServer

    init {
        dnsRegistry = DnsRegistry()
        domainManager = DomainManager(dnsRegistry)

        udpServer = UDPServer(domainManager)
    }

    fun start() {
        udpServer.start()
    }

    fun stop() {
        udpServer.stop()
    }

}
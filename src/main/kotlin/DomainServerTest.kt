import net.cakemc.dns.DomainNameServer
import net.cakemc.dns.register.ZoneId
import net.cakemc.dns.records.AAAARecord
import net.cakemc.dns.records.ARecord

fun main() {
    val domainServer = DomainNameServer()

    val zoneId = ZoneId("example.com")
    val dnsZone = domainServer.dnsRegistry.registerZone(zoneId)

    domainServer.dnsRegistry.addRecordToZone(zoneId, ARecord(
        "192.168.178.145", "example.com", 440
    ))
    domainServer.dnsRegistry.addRecordToZone(zoneId, AAAARecord(
            "2606:2800:220:1:248:1893:25c8:1946", "example.com",3600
        )
    )

    domainServer.start()
}

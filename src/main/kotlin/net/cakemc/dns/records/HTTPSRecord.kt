package net.cakemc.dns.records

import net.cakemc.dns.types.DNSRecordType
import net.cakemc.dns.DnsRecord

// HTTPS Record (RFC 9460 — special case of SVCB)
data class HTTPSRecord(
    val priority: Int,
    val targetName: String,
    val params: Map<String, String>,
    val nameInt: String,
    val ttlInt: Int
) : DnsRecord(nameInt, ttlInt, type = DNSRecordType.HTTPS) {

    constructor(): this(0, "", emptyMap(), "", 0)

    override fun encode(): ByteArray = SVCBRecord(priority, targetName, params, nameInt, ttlInt).encode()

    override fun decode(byteArray: ByteArray): HTTPSRecord {
        val svcb = SVCBRecord(0, "", emptyMap(), nameInt, ttlInt).decode(byteArray)
        return HTTPSRecord(svcb.priority, svcb.targetName, svcb.params, svcb.nameInt, svcb.ttlInt)
    }

}
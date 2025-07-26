package net.cakemc.dns.records

import net.cakemc.dns.types.DNSRecordType
import net.cakemc.dns.units.DNSUtils
import net.cakemc.dns.DnsRecord
import java.nio.ByteBuffer

// CNAME Record (Canonical Name)
data class CNAMERecord(
    val canonicalName: String,
    val nameInt: String,
    val ttlInt: Int
) : DnsRecord(nameInt, ttlInt, type = DNSRecordType.CNAME) {

    constructor(): this("", "", 0)

    override fun encode(): ByteArray {
        val nameBytes = DNSUtils.encodeDomainName(nameInt)
        val cnameBytes = DNSUtils.encodeDomainName(canonicalName)
        val buffer = ByteBuffer.allocate(nameBytes.size + 10 + cnameBytes.size)
        buffer.put(nameBytes)
        buffer.putShort(DNSRecordType.CNAME.code.toShort())
        buffer.putShort(1)
        buffer.putInt(ttlInt)
        buffer.putShort(cnameBytes.size.toShort())
        buffer.put(cnameBytes)
        return buffer.array()
    }

    override fun decode(byteArray: ByteArray): CNAMERecord {
        var pos = 0
        val (name, nameEnd) = DNSUtils.decodeDomainName(byteArray, pos)
        pos = nameEnd + 8
        val rdlength = ByteBuffer.wrap(byteArray, pos, 2).short.toInt()
        pos += 2
        val (cname, _) = DNSUtils.decodeDomainName(byteArray, pos)
        return CNAMERecord(cname, name, ttlInt)
    }

}
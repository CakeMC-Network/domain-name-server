package net.cakemc.dns.records

import net.cakemc.dns.types.DNSRecordType
import net.cakemc.dns.units.DNSUtils
import net.cakemc.dns.DnsRecord
import java.nio.ByteBuffer

// NS Record (Name Server)
data class NSRecord(
    val nsdName: String, // Authoritative nameserver
    val nameInt: String,
    val ttlInt: Int
) : DnsRecord(nameInt, ttlInt, type = DNSRecordType.NS) {

    constructor(): this("", "", 0)

    override fun encode(): ByteArray {
        val nameBytes = DNSUtils.encodeDomainName(nameInt)
        val nsBytes = DNSUtils.encodeDomainName(nsdName)
        val buffer = ByteBuffer.allocate(nameBytes.size + 10 + nsBytes.size)
        buffer.put(nameBytes)
        buffer.putShort(DNSRecordType.NS.code.toShort())
        buffer.putShort(1)
        buffer.putInt(ttlInt)
        buffer.putShort(nsBytes.size.toShort())
        buffer.put(nsBytes)
        return buffer.array()
    }

    override fun decode(byteArray: ByteArray): NSRecord {
        var pos = 0
        val (name, nameEnd) = DNSUtils.decodeDomainName(byteArray, pos)
        pos = nameEnd + 8
        val rdlength = ByteBuffer.wrap(byteArray, pos, 2).short.toInt()
        pos += 2
        val (nsd, _) = DNSUtils.decodeDomainName(byteArray, pos)
        return NSRecord(nsd, name, ttlInt)
    }


}


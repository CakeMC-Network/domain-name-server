package net.cakemc.dns.records

import net.cakemc.dns.types.DNSRecordType
import net.cakemc.dns.units.DNSUtils
import net.cakemc.dns.DnsRecord
import java.nio.ByteBuffer

// URI Record (RFC 7553)
data class URIRecord(
    val priority: Int,
    val weight: Int,
    val target: String, // URI string
    val nameInt: String,
    val ttlInt: Int
) : DnsRecord(nameInt, ttlInt, type = DNSRecordType.URI) {

    constructor(): this(0, 0, "", "", 0)

    override fun encode(): ByteArray {
        val nameBytes = DNSUtils.encodeDomainName(nameInt)
        val targetBytes = target.toByteArray()
        val rdataLen = 4 + targetBytes.size
        val buffer = ByteBuffer.allocate(nameBytes.size + 10 + rdataLen)
        buffer.put(nameBytes)
        buffer.putShort(DNSRecordType.URI.code.toShort())
        buffer.putShort(1)
        buffer.putInt(ttlInt)
        buffer.putShort(rdataLen.toShort())
        buffer.putShort(priority.toShort())
        buffer.putShort(weight.toShort())
        buffer.put(targetBytes)
        return buffer.array()
    }

    override fun decode(byteArray: ByteArray): URIRecord {
        var pos = 0
        val (name, nameEnd) = DNSUtils.decodeDomainName(byteArray, pos)
        pos = nameEnd + 8
        val rdlength = ByteBuffer.wrap(byteArray, pos, 2).short.toInt(); pos += 2
        val priority = ByteBuffer.wrap(byteArray, pos, 2).short.toInt(); pos += 2
        val weight = ByteBuffer.wrap(byteArray, pos, 2).short.toInt(); pos += 2
        val target = byteArray.copyOfRange(pos, pos + rdlength - 4).toString(Charsets.UTF_8)
        return URIRecord(priority, weight, target, name, ttlInt)
    }


}
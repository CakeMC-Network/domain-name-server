package net.cakemc.dns.records

import net.cakemc.dns.types.DNSRecordType
import net.cakemc.dns.units.DNSUtils
import net.cakemc.dns.DnsRecord
import java.nio.ByteBuffer

// SRV Record (Service Locator)
data class SRVRecord(
    val priority: Int,
    val weight: Int,
    val port: Int,
    val target: String,
    val nameInt: String,
    val ttlInt: Int
) : DnsRecord(nameInt, ttlInt, type = DNSRecordType.SRV) {

    constructor(): this(0, 0, 0, "", "", 0)

    override fun encode(): ByteArray {
        val nameBytes = DNSUtils.encodeDomainName(nameInt)
        val targetBytes = DNSUtils.encodeDomainName(target)
        val rdataLen = 6 + targetBytes.size
        val buffer = ByteBuffer.allocate(nameBytes.size + 10 + rdataLen)
        buffer.put(nameBytes)
        buffer.putShort(DNSRecordType.SRV.code.toShort())
        buffer.putShort(1)
        buffer.putInt(ttlInt)
        buffer.putShort(rdataLen.toShort())
        buffer.putShort(priority.toShort())
        buffer.putShort(weight.toShort())
        buffer.putShort(port.toShort())
        buffer.put(targetBytes)
        return buffer.array()
    }

    override fun decode(byteArray: ByteArray): SRVRecord {
        var pos = 0
        val (name, nameEnd) = DNSUtils.decodeDomainName(byteArray, pos)
        pos = nameEnd + 8
        val rdlength = ByteBuffer.wrap(byteArray, pos, 2).short.toInt()
        pos += 2
        val prio = ByteBuffer.wrap(byteArray, pos, 2).short.toInt()
        val weight = ByteBuffer.wrap(byteArray, pos + 2, 2).short.toInt()
        val port = ByteBuffer.wrap(byteArray, pos + 4, 2).short.toInt()
        pos += 6
        val (target, _) = DNSUtils.decodeDomainName(byteArray, pos)
        return SRVRecord(prio, weight, port, target, name, ttlInt)
    }


}
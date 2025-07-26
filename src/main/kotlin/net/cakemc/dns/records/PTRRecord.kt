package net.cakemc.dns.records

import net.cakemc.dns.types.DNSRecordType
import net.cakemc.dns.units.DNSUtils
import net.cakemc.dns.DnsRecord
import java.nio.ByteBuffer

// PTR Record (Pointer - Reverse DNS)
data class PTRRecord(
    val ptrDomainName: String,
    val nameInt: String,
    val ttlInt: Int
) : DnsRecord(nameInt, ttlInt, type = DNSRecordType.PTR) {

    constructor(): this("", "", 0)

    override fun encode(): ByteArray {
        val nameBytes = DNSUtils.encodeDomainName(nameInt)
        val ptrBytes = DNSUtils.encodeDomainName(ptrDomainName)
        val buffer = ByteBuffer.allocate(nameBytes.size + 10 + ptrBytes.size)
        buffer.put(nameBytes)
        buffer.putShort(DNSRecordType.PTR.code.toShort())
        buffer.putShort(1) // class IN
        buffer.putInt(ttlInt)
        buffer.putShort(ptrBytes.size.toShort())
        buffer.put(ptrBytes)
        return buffer.array()
    }

    override fun decode(byteArray: ByteArray): PTRRecord {
        var pos = 0
        val (name, nameEnd) = DNSUtils.decodeDomainName(byteArray, pos)
        pos = nameEnd + 8
        val rdlength = ByteBuffer.wrap(byteArray, pos, 2).short.toInt()
        pos += 2
        val (ptr, _) = DNSUtils.decodeDomainName(byteArray, pos)
        return PTRRecord(ptr, name, ttlInt)
    }


}
package net.cakemc.dns.records

import net.cakemc.dns.types.DNSRecordType
import net.cakemc.dns.units.DNSUtils
import net.cakemc.dns.DnsRecord
import java.nio.ByteBuffer

// Generic UNKNOWN Record (for future-proofing)
data class UnknownRecord(
    val typeCode: Int,
    val data: String,
    val nameInt: String,
    val ttlInt: Int
) : DnsRecord(nameInt, ttlInt, type = DNSRecordType.Unknown) {

    constructor(): this(0, "", "", 0)

    override fun encode(): ByteArray {
        val nameBytes = DNSUtils.encodeDomainName(nameInt)
        val dataBytes = data.toByteArray()
        val buffer = ByteBuffer.allocate(nameBytes.size + 10 + dataBytes.size)
        buffer.put(nameBytes)
        buffer.putShort(typeCode.toShort())
        buffer.putShort(1)
        buffer.putInt(ttlInt)
        buffer.putShort(dataBytes.size.toShort())
        buffer.put(dataBytes)
        return buffer.array()
    }

    override fun decode(byteArray: ByteArray): UnknownRecord {
        var pos = 0
        val (name, nameEnd) = DNSUtils.decodeDomainName(byteArray, pos)
        val typeCode = ByteBuffer.wrap(byteArray, nameEnd, 2).short.toInt()
        pos = nameEnd + 8
        val rdlength = ByteBuffer.wrap(byteArray, pos, 2).short.toInt(); pos += 2
        val dataStr = byteArray.copyOfRange(pos, pos + rdlength).toString(Charsets.UTF_8)
        return UnknownRecord(typeCode, dataStr, name, ttlInt)
    }


}
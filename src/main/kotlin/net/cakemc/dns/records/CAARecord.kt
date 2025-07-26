package net.cakemc.dns.records

import net.cakemc.dns.types.DNSRecordType
import net.cakemc.dns.units.DNSUtils
import net.cakemc.dns.DnsRecord
import java.nio.ByteBuffer

// CAA Record (Certification Authority Authorization)
data class CAARecord(
    val flag: Int,
    val tag: String,        // e.g., issue, issuewild, iodef
    val value: String,
    val nameInt: String,
    val ttlInt: Int
) : DnsRecord(nameInt, ttlInt, type = DNSRecordType.CAA) {


    constructor(): this(0, "", "", "", 0)

    override fun encode(): ByteArray {
        val nameBytes = DNSUtils.encodeDomainName(nameInt)
        val tagBytes = tag.toByteArray()
        val valueBytes = value.toByteArray()
        val rdataLen = 1 + 1 + tagBytes.size + valueBytes.size

        val buffer = ByteBuffer.allocate(nameBytes.size + 10 + rdataLen)
        buffer.put(nameBytes)
        buffer.putShort(DNSRecordType.CAA.code.toShort())
        buffer.putShort(1)
        buffer.putInt(ttlInt)
        buffer.putShort(rdataLen.toShort())
        buffer.put(flag.toByte())
        buffer.put(tagBytes.size.toByte())
        buffer.put(tagBytes)
        buffer.put(valueBytes)
        return buffer.array()
    }

    override fun decode(byteArray: ByteArray): CAARecord {
        var pos = 0
        val (name, nameEnd) = DNSUtils.decodeDomainName(byteArray, pos)
        pos = nameEnd + 8
        val rdlength = ByteBuffer.wrap(byteArray, pos, 2).short.toInt(); pos += 2

        val flag = byteArray[pos++].toInt()
        val tagLen = byteArray[pos++].toInt()
        val tag = byteArray.copyOfRange(pos, pos + tagLen).toString(Charsets.UTF_8); pos += tagLen
        val value = byteArray.copyOfRange(pos, pos + (rdlength - 2 - tagLen)).toString(Charsets.UTF_8)

        return CAARecord(flag, tag, value, name, ttlInt)
    }


}
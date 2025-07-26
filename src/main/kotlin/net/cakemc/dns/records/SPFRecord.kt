package net.cakemc.dns.records

import net.cakemc.dns.types.DNSRecordType
import net.cakemc.dns.units.DNSUtils
import net.cakemc.dns.DnsRecord
import java.nio.ByteBuffer

// SPF Record (Deprecated, but still used)
data class SPFRecord(
    val data: String, // SPF policy string (same as TXT, historically separate)
    val nameInt: String,
    val ttlInt: Int
) : DnsRecord(nameInt, ttlInt, type = DNSRecordType.SPF) {

    constructor(): this("", "", 0)

    override fun encode(): ByteArray {
        val nameBytes = DNSUtils.encodeDomainName(nameInt)
        val dataBytes = data.toByteArray()
        val txtBytes = byteArrayOf(dataBytes.size.toByte()) + dataBytes
        val buffer = ByteBuffer.allocate(nameBytes.size + 10 + txtBytes.size)
        buffer.put(nameBytes)
        buffer.putShort(DNSRecordType.SPF.code.toShort())
        buffer.putShort(1)
        buffer.putInt(ttlInt)
        buffer.putShort(txtBytes.size.toShort())
        buffer.put(txtBytes)
        return buffer.array()
    }

    override fun decode(byteArray: ByteArray): SPFRecord {
        var pos = 0
        val (name, nameEnd) = DNSUtils.decodeDomainName(byteArray, pos)
        pos = nameEnd + 8
        val rdlength = ByteBuffer.wrap(byteArray, pos, 2).short.toInt(); pos += 2
        val txtLen = byteArray[pos++].toInt()
        val str = byteArray.copyOfRange(pos, pos + txtLen).toString(Charsets.UTF_8)
        return SPFRecord(str, name, ttlInt)
    }


}
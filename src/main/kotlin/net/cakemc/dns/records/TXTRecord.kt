package net.cakemc.dns.records

import net.cakemc.dns.types.DNSRecordType
import net.cakemc.dns.units.DNSUtils
import net.cakemc.dns.DnsRecord
import java.nio.ByteBuffer

// TXT Record (Text)
data class TXTRecord(
    val texts: List<String>,
    val nameInt: String,
    val ttlInt: Int
) : DnsRecord(nameInt, ttlInt, type = DNSRecordType.TXT) {

    constructor(): this(emptyList(), "", 0)

    override fun encode(): ByteArray {
        val nameBytes = DNSUtils.encodeDomainName(nameInt)
        val txtBytes = texts.flatMap { str ->
            val strBytes = str.toByteArray()
            listOf(strBytes.size.toByte()) + strBytes.toList()
        }.toByteArray()
        val buffer = ByteBuffer.allocate(nameBytes.size + 10 + txtBytes.size)
        buffer.put(nameBytes)
        buffer.putShort(DNSRecordType.TXT.code.toShort())
        buffer.putShort(1)
        buffer.putInt(ttlInt)
        buffer.putShort(txtBytes.size.toShort())
        buffer.put(txtBytes)
        return buffer.array()
    }

    override fun decode(byteArray: ByteArray): TXTRecord {
        var pos = 0
        val (name, nameEnd) = DNSUtils.decodeDomainName(byteArray, pos)
        pos = nameEnd + 8
        val rdlength = ByteBuffer.wrap(byteArray, pos, 2).short.toInt()
        pos += 2
        val texts = mutableListOf<String>()
        val end = pos + rdlength
        while (pos < end) {
            val len = byteArray[pos].toInt()
            pos++
            val str = byteArray.copyOfRange(pos, pos + len).toString(Charsets.UTF_8)
            texts.add(str)
            pos += len
        }
        return TXTRecord(texts, name, ttlInt)
    }


}
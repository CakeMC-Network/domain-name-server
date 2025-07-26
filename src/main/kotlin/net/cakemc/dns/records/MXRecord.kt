package net.cakemc.dns.records

import net.cakemc.dns.types.DNSRecordType
import net.cakemc.dns.units.DNSUtils
import net.cakemc.dns.DnsRecord
import java.nio.ByteBuffer

// MX Record (Mail Exchange)
data class MXRecord(
    val preference: Int,
    val exchange: String,
    val nameInt: String,
    val ttlInt: Int
) : DnsRecord(nameInt, ttlInt, type = DNSRecordType.MX) {

    constructor(): this(0, "", "", 0)

    override fun encode(): ByteArray {
        val nameBytes = DNSUtils.encodeDomainName(nameInt)
        val exchangeBytes = DNSUtils.encodeDomainName(exchange)
        val buffer = ByteBuffer.allocate(nameBytes.size + 10 + 2 + exchangeBytes.size)
        buffer.put(nameBytes)
        buffer.putShort(DNSRecordType.MX.code.toShort())
        buffer.putShort(1)
        buffer.putInt(ttlInt)
        buffer.putShort((2 + exchangeBytes.size).toShort())
        buffer.putShort(preference.toShort())
        buffer.put(exchangeBytes)
        return buffer.array()
    }

    override fun decode(byteArray: ByteArray): MXRecord {
        var pos = 0
        val (name, nameEnd) = DNSUtils.decodeDomainName(byteArray, pos)
        pos = nameEnd + 8
        val rdlength = ByteBuffer.wrap(byteArray, pos, 2).short.toInt()
        pos += 2
        val pref = ByteBuffer.wrap(byteArray, pos, 2).short.toInt()
        pos += 2
        val (exch, _) = DNSUtils.decodeDomainName(byteArray, pos)
        return MXRecord(pref, exch, name, ttlInt)
    }


}
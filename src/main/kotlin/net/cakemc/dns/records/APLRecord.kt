package net.cakemc.dns.records

import net.cakemc.dns.types.DNSRecordType
import net.cakemc.dns.units.DNSUtils
import net.cakemc.dns.DnsRecord
import java.net.InetAddress
import java.nio.ByteBuffer

// APL Record (RFC 3123)
data class APLRecord(
    val addressFamily: Int, // e.g., 1 = IPv4, 2 = IPv6
    val prefix: String,
    val negation: Boolean,
    val nameInt: String,
    val ttlInt: Int
) : DnsRecord(nameInt, ttlInt, type = DNSRecordType.APL) {

    constructor(): this(0, "", false, "", 0)

    override fun encode(): ByteArray {
        val nameBytes = DNSUtils.encodeDomainName(nameInt)
        val prefixBytes = InetAddress.getByName(prefix).address
        val length = prefixBytes.size
        val flagLength = (if (negation) 0x80 else 0x00) or length
        val rdata = ByteBuffer.allocate(4 + length)
        rdata.putShort(addressFamily.toShort())
        rdata.put(prefix.split("/")[1].toInt().toByte()) // prefix length
        rdata.put(flagLength.toByte())
        rdata.put(prefixBytes)
        val rdataArr = rdata.array()
        val buffer = ByteBuffer.allocate(nameBytes.size + 10 + rdataArr.size)
        buffer.put(nameBytes)
        buffer.putShort(DNSRecordType.APL.code.toShort())
        buffer.putShort(1)
        buffer.putInt(ttlInt)
        buffer.putShort(rdataArr.size.toShort())
        buffer.put(rdataArr)
        return buffer.array()
    }

    override fun decode(byteArray: ByteArray): APLRecord {
        var pos = 0
        val (name, nameEnd) = DNSUtils.decodeDomainName(byteArray, pos)
        pos = nameEnd + 8
        val rdlen = ByteBuffer.wrap(byteArray, pos, 2).short.toInt()
        pos += 2
        val family = ByteBuffer.wrap(byteArray, pos, 2).short.toInt(); pos += 2
        val prefixLen = byteArray[pos++].toInt()
        val flagsLength = byteArray[pos++].toInt()
        val neg = (flagsLength and 0x80) != 0
        val addrLen = flagsLength and 0x7F
        val addrBytes = byteArray.copyOfRange(pos, pos + addrLen)
        val addrStr = InetAddress.getByAddress(addrBytes).hostAddress
        val prefixStr = "$addrStr/$prefixLen"
        return APLRecord(family, prefixStr, neg, name, ttlInt)
    }


}
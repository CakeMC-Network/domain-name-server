package net.cakemc.dns.records

import net.cakemc.dns.types.DNSRecordType
import net.cakemc.dns.units.DNSUtils
import net.cakemc.dns.DnsRecord
import java.nio.ByteBuffer
import java.util.*

// TLSA Record (RFC 6698)
data class TLSARecord(
    val usage: Int,
    val selector: Int,
    val matchingType: Int,
    val certificateAssociationData: String,
    val nameInt: String,
    val ttlInt: Int
) : DnsRecord(nameInt, ttlInt, type = DNSRecordType.TLSA) {

    constructor(): this(0, 0, 0, "", "", 0)

    override fun encode(): ByteArray {
        val nameBytes = DNSUtils.encodeDomainName(nameInt)
        val certBytes = Base64.getDecoder().decode(certificateAssociationData)
        val rdataLen = 3 + certBytes.size
        val buffer = ByteBuffer.allocate(nameBytes.size + 10 + rdataLen)
        buffer.put(nameBytes)
        buffer.putShort(DNSRecordType.TLSA.code.toShort())
        buffer.putShort(1)
        buffer.putInt(ttlInt)
        buffer.putShort(rdataLen.toShort())
        buffer.put(usage.toByte())
        buffer.put(selector.toByte())
        buffer.put(matchingType.toByte())
        buffer.put(certBytes)
        return buffer.array()
    }

    override fun decode(byteArray: ByteArray): TLSARecord {
        var pos = 0
        val (name, nameEnd) = DNSUtils.decodeDomainName(byteArray, pos)
        pos = nameEnd + 8
        val rdlength = ByteBuffer.wrap(byteArray, pos, 2).short.toInt(); pos += 2
        val usage = byteArray[pos++].toInt()
        val selector = byteArray[pos++].toInt()
        val matchingType = byteArray[pos++].toInt()
        val certBytes = byteArray.copyOfRange(pos, pos + rdlength - 3)
        val certStr = Base64.getEncoder().encodeToString(certBytes)
        return TLSARecord(usage, selector, matchingType, certStr, name, ttlInt)
    }


}
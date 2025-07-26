package net.cakemc.dns.records

import net.cakemc.dns.types.DNSRecordType
import net.cakemc.dns.units.DNSUtils
import net.cakemc.dns.DnsRecord
import java.nio.ByteBuffer
import java.util.*

// CERT Record (RFC 4398)
data class CERTRecord(
    val certType: Int,
    val keyTag: Int,
    val algorithm: Int,
    val certificate: String,
    val nameInt: String,
    val ttlInt: Int
) : DnsRecord(nameInt, ttlInt, type = DNSRecordType.CERT) {

    constructor(): this(0, 0, 0, "", "", 0)

    override fun encode(): ByteArray {
        val nameBytes = DNSUtils.encodeDomainName(nameInt)
        val certBytes = Base64.getDecoder().decode(certificate)
        val rdataLen = 5 + certBytes.size
        val buffer = ByteBuffer.allocate(nameBytes.size + 10 + rdataLen)
        buffer.put(nameBytes)
        buffer.putShort(DNSRecordType.CERT.code.toShort())
        buffer.putShort(1)
        buffer.putInt(ttlInt)
        buffer.putShort(rdataLen.toShort())
        buffer.putShort(certType.toShort())
        buffer.putShort(keyTag.toShort())
        buffer.put(algorithm.toByte())
        buffer.put(certBytes)
        return buffer.array()
    }

    override fun decode(byteArray: ByteArray): CERTRecord {
        var pos = 0
        val (name, nameEnd) = DNSUtils.decodeDomainName(byteArray, pos)
        pos = nameEnd + 8
        val rdlength = ByteBuffer.wrap(byteArray, pos, 2).short.toInt(); pos += 2
        val certType = ByteBuffer.wrap(byteArray, pos, 2).short.toInt(); pos += 2
        val keyTag = ByteBuffer.wrap(byteArray, pos, 2).short.toInt(); pos += 2
        val algorithm = byteArray[pos++].toInt()
        val certBytes = byteArray.copyOfRange(pos, pos + rdlength - 5)
        val certStr = Base64.getEncoder().encodeToString(certBytes)
        return CERTRecord(certType, keyTag, algorithm, certStr, name, ttlInt)
    }

}
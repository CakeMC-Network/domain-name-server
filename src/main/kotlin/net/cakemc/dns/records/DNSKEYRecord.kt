package net.cakemc.dns.records

import net.cakemc.dns.types.DNSRecordType
import net.cakemc.dns.units.DNSUtils
import net.cakemc.dns.DnsRecord
import java.nio.ByteBuffer
import java.util.*

// DNSKEY Record (DNSSEC Public Key)
data class DNSKEYRecord(
    val flags: Int,
    val protocol: Int,
    val algorithm: Int,
    val publicKey: String,
    val nameInt: String,
    val ttlInt: Int
) : DnsRecord(nameInt, ttlInt, type = DNSRecordType.DNSKEY) {

    constructor(): this(0, 0, 0, "", "", 0)

    override fun encode(): ByteArray {
        val nameBytes = DNSUtils.encodeDomainName(nameInt)
        val pubKeyBytes = Base64.getDecoder().decode(publicKey)
        val rdataLen = 4 + pubKeyBytes.size

        val buffer = ByteBuffer.allocate(nameBytes.size + 10 + rdataLen)
        buffer.put(nameBytes)
        buffer.putShort(DNSRecordType.DNSKEY.code.toShort())
        buffer.putShort(1)
        buffer.putInt(ttlInt)
        buffer.putShort(rdataLen.toShort())
        buffer.putShort(flags.toShort())
        buffer.put(protocol.toByte())
        buffer.put(algorithm.toByte())
        buffer.put(pubKeyBytes)
        return buffer.array()
    }

    override fun decode(byteArray: ByteArray): DNSKEYRecord {
        var pos = 0
        val (name, nameEnd) = DNSUtils.decodeDomainName(byteArray, pos)
        pos = nameEnd + 8
        val rdlength = ByteBuffer.wrap(byteArray, pos, 2).short.toInt(); pos += 2

        val flags = ByteBuffer.wrap(byteArray, pos, 2).short.toInt(); pos += 2
        val protocol = byteArray[pos++].toInt()
        val algorithm = byteArray[pos++].toInt()
        val pubKeyBytes = byteArray.copyOfRange(pos, pos + rdlength - 4)
        val publicKey = Base64.getEncoder().encodeToString(pubKeyBytes)

        return DNSKEYRecord(flags, protocol, algorithm, publicKey, name, ttlInt)
    }


}
package net.cakemc.dns.records

import net.cakemc.dns.types.DNSRecordType
import net.cakemc.dns.units.DNSUtils
import net.cakemc.dns.DnsRecord
import java.nio.ByteBuffer
import java.time.LocalDateTime
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import java.util.*

// RRSIG Record (DNSSEC Signature)
data class RRSIGRecord(
    val typeCovered: String,
    val algorithm: Int,
    val labels: Int,
    val originalTTL: Int,
    val signatureExpiration: String,
    val signatureInception: String,
    val keyTag: Int,
    val signerName: String,
    val signature: String,
    val nameInt: String,
    val ttlInt: Int
) : DnsRecord(nameInt, ttlInt, type = DNSRecordType.RRSIG) {

    constructor(): this("", 0, 0, 0, "", "", 0, "", "", "", 0)

    override fun encode(): ByteArray {
        val nameBytes = DNSUtils.encodeDomainName(nameInt)
        val signerBytes = DNSUtils.encodeDomainName(signerName)
        val sigBytes = Base64.getDecoder().decode(signature)

        val typeCoveredCode = DNSRecordType.valueOf(typeCovered).code
        val buffer = ByteBuffer.allocate(nameBytes.size + 10 + 18 + signerBytes.size + sigBytes.size)
        buffer.put(nameBytes)
        buffer.putShort(DNSRecordType.RRSIG.code.toShort())
        buffer.putShort(1)
        buffer.putInt(ttlInt)
        val rdataLen = 18 + signerBytes.size + sigBytes.size
        buffer.putShort(rdataLen.toShort())
        buffer.putShort(typeCoveredCode.toShort())
        buffer.put(algorithm.toByte())
        buffer.put(labels.toByte())
        buffer.putInt(originalTTL)
        val formatter = DateTimeFormatter.ofPattern("yyyyMMddHHmmss").withZone(ZoneOffset.UTC)

        val sigExpEpoch = LocalDateTime.parse(signatureExpiration, formatter).toEpochSecond(ZoneOffset.UTC)
        val sigIncEpoch = LocalDateTime.parse(signatureInception, formatter).toEpochSecond(ZoneOffset.UTC)

        buffer.putInt(sigExpEpoch.toInt())  // Use only 4 bytes (lower 32 bits)
        buffer.putInt(sigIncEpoch.toInt())

        buffer.putShort(keyTag.toShort())
        buffer.put(signerBytes)
        buffer.put(sigBytes)
        return buffer.array()
    }

    override fun decode(byteArray: ByteArray): RRSIGRecord {
        var pos = 0
        val (name, nameEnd) = DNSUtils.decodeDomainName(byteArray, pos)
        pos = nameEnd + 8
        val rdlength = ByteBuffer.wrap(byteArray, pos, 2).short.toInt(); pos += 2

        val typeCoveredCode = ByteBuffer.wrap(byteArray, pos, 2).short.toInt(); pos += 2
        val algorithm = byteArray[pos++].toInt()
        val labels = byteArray[pos++].toInt()
        val origTTL = ByteBuffer.wrap(byteArray, pos, 4).int; pos += 4
        val sigExpire = ByteBuffer.wrap(byteArray, pos, 4).int.toString(); pos += 4
        val sigIncept = ByteBuffer.wrap(byteArray, pos, 4).int.toString(); pos += 4
        val keyTag = ByteBuffer.wrap(byteArray, pos, 2).short.toInt(); pos += 2
        val (signer, signerEnd) = DNSUtils.decodeDomainName(byteArray, pos)
        val signature = Base64.getEncoder().encodeToString(byteArray.copyOfRange(signerEnd, pos + rdlength))

        return RRSIGRecord(
            typeCovered = DNSRecordType.fromCode(typeCoveredCode).name,
            algorithm, labels, origTTL, sigExpire, sigIncept, keyTag, signer, signature, name, ttlInt
        )
    }

}
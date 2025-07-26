package net.cakemc.dns.records

import net.cakemc.dns.types.DNSRecordType
import net.cakemc.dns.units.DNSUtils
import net.cakemc.dns.DnsRecord
import java.nio.ByteBuffer

// DS Record (Delegation Signer)
data class DSRecord(
    val keyTag: Int,
    val algorithm: Int,
    val digestType: Int,
    val digest: String,
    val nameInt: String,
    val ttlInt: Int
) : DnsRecord(nameInt, ttlInt, type = DNSRecordType.DS) {

    override fun encode(): ByteArray {
        val nameBytes = DNSUtils.encodeDomainName(nameInt)
        val digestBytes = DNSUtils.hexStringToByteArray(digest) // or Base64 if your digest is encoded
        val rdataLen = 4 + digestBytes.size
        val buffer = ByteBuffer.allocate(nameBytes.size + 10 + rdataLen)
        buffer.put(nameBytes)
        buffer.putShort(DNSRecordType.DS.code.toShort())
        buffer.putShort(1)
        buffer.putInt(ttlInt)
        buffer.putShort(rdataLen.toShort())
        buffer.putShort(keyTag.toShort())
        buffer.put(algorithm.toByte())
        buffer.put(digestType.toByte())
        buffer.put(digestBytes)
        return buffer.array()
    }

    override fun decode(byteArray: ByteArray): DSRecord {
        var pos = 0
        val (name, nameEnd) = DNSUtils.decodeDomainName(byteArray, pos)
        pos = nameEnd + 8
        val rdlength = ByteBuffer.wrap(byteArray, pos, 2).short.toInt(); pos += 2
        val keyTag = ByteBuffer.wrap(byteArray, pos, 2).short.toInt(); pos += 2
        val algorithm = byteArray[pos++].toInt()
        val digestType = byteArray[pos++].toInt()
        val digestBytes = byteArray.copyOfRange(pos, pos + (rdlength - 4))
        val digest = DNSUtils.byteArrayToHex(digestBytes)
        return DSRecord(keyTag, algorithm, digestType, digest, name, ttlInt)
    }


}
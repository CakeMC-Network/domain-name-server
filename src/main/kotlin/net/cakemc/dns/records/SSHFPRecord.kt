package net.cakemc.dns.records

import net.cakemc.dns.types.DNSRecordType
import net.cakemc.dns.units.DNSUtils
import net.cakemc.dns.DnsRecord
import java.nio.ByteBuffer

// SSHFP Record (RFC 4255)
data class SSHFPRecord(
    val algorithm: Int,
    val fingerprintType: Int,
    val fingerprint: String,
    val nameInt: String,
    val ttlInt: Int
) : DnsRecord(nameInt, ttlInt, type = DNSRecordType.SSHFP) {

    constructor(): this(0, 0, "", "", 0)

    override fun encode(): ByteArray {
        val nameBytes = DNSUtils.encodeDomainName(nameInt)
        val fpBytes = DNSUtils.hexStringToByteArray(fingerprint)
        val rdata = byteArrayOf(algorithm.toByte(), fingerprintType.toByte()) + fpBytes
        val buffer = ByteBuffer.allocate(nameBytes.size + 10 + rdata.size)
        buffer.put(nameBytes)
        buffer.putShort(DNSRecordType.SSHFP.code.toShort())
        buffer.putShort(1)
        buffer.putInt(ttlInt)
        buffer.putShort(rdata.size.toShort())
        buffer.put(rdata)
        return buffer.array()
    }

    override fun decode(byteArray: ByteArray): SSHFPRecord {
        var pos = 0
        val (name, nameEnd) = DNSUtils.decodeDomainName(byteArray, pos)
        pos = nameEnd + 8
        val rdlen = ByteBuffer.wrap(byteArray, pos, 2).short.toInt(); pos += 2
        val algorithm = byteArray[pos++].toInt()
        val fpType = byteArray[pos++].toInt()
        val fp = byteArray.copyOfRange(pos, pos + rdlen - 2)
        return SSHFPRecord(algorithm, fpType, DNSUtils.byteArrayToHex(fp), name, ttlInt)
    }


}
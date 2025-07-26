package net.cakemc.dns.records

import net.cakemc.dns.types.DNSRecordType
import net.cakemc.dns.units.DNSUtils
import net.cakemc.dns.DnsRecord
import java.nio.ByteBuffer

// SOA Record (Start of Authority)
data class SOARecord(
    val mName: String,       // Primary master name server
    val rName: String,       // Responsible party email
    val serial: Long,
    val refresh: Long,
    val retry: Long,
    val expire: Long,
    val minimumTTL: Long,
    val nameInt: String,
    val ttlInt: Int
) : DnsRecord(nameInt, ttlInt, type = DNSRecordType.SOA) {

    constructor(): this("", "", 0,0,0, 0, 0, "", 0)

    override fun encode(): ByteArray {
        val nameBytes = DNSUtils.encodeDomainName(nameInt)
        val mNameBytes = DNSUtils.encodeDomainName(mName)
        val rNameBytes = DNSUtils.encodeDomainName(rName)
        val rdataSize = mNameBytes.size + rNameBytes.size + 20
        val buffer = ByteBuffer.allocate(nameBytes.size + 10 + rdataSize)
        buffer.put(nameBytes)
        buffer.putShort(DNSRecordType.SOA.code.toShort())
        buffer.putShort(1)
        buffer.putInt(ttlInt)
        buffer.putShort(rdataSize.toShort())
        buffer.put(mNameBytes)
        buffer.put(rNameBytes)
        buffer.putInt(serial.toInt()) // Assuming Int for simplicity
        buffer.putInt(refresh.toInt())
        buffer.putInt(retry.toInt())
        buffer.putInt(expire.toInt())
        buffer.putInt(minimumTTL.toInt())
        return buffer.array()
    }

    override fun decode(byteArray: ByteArray): SOARecord {
        var pos = 0
        val (name, nameEnd) = DNSUtils.decodeDomainName(byteArray, pos)
        pos = nameEnd + 8
        val rdlength = ByteBuffer.wrap(byteArray, pos, 2).short.toInt()
        pos += 2
        val (mName, mEnd) = DNSUtils.decodeDomainName(byteArray, pos)
        val (rName, rEnd) = DNSUtils.decodeDomainName(byteArray, mEnd)
        val buffer = ByteBuffer.wrap(byteArray, rEnd, 20)
        return SOARecord(
            mName, rName,
            buffer.int.toLong(), buffer.int.toLong(), buffer.int.toLong(),
            buffer.int.toLong(), buffer.int.toLong(), name, ttlInt
        )
    }


}
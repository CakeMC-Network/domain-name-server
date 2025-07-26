package net.cakemc.dns.records

import net.cakemc.dns.types.DNSRecordType
import net.cakemc.dns.units.DNSUtils
import net.cakemc.dns.DnsRecord
import java.nio.ByteBuffer

// HINFO Record (RFC 8482)
data class HINFORecord(
    val cpu: String,
    val os: String,
    val nameInt: String,
    val ttlInt: Int
) : DnsRecord(nameInt, ttlInt, type = DNSRecordType.HINFO) {

    constructor(): this("", "", "", 0)

    override fun encode(): ByteArray {
        val nameBytes = DNSUtils.encodeDomainName(nameInt)
        val cpuBytes = cpu.toByteArray()
        val osBytes = os.toByteArray()
        val rdata = byteArrayOf(cpuBytes.size.toByte()) + cpuBytes + byteArrayOf(osBytes.size.toByte()) + osBytes
        val buffer = ByteBuffer.allocate(nameBytes.size + 10 + rdata.size)
        buffer.put(nameBytes)
        buffer.putShort(DNSRecordType.HINFO.code.toShort())
        buffer.putShort(1)
        buffer.putInt(ttlInt)
        buffer.putShort(rdata.size.toShort())
        buffer.put(rdata)
        return buffer.array()
    }

    override fun decode(byteArray: ByteArray): HINFORecord {
        var pos = 0
        val (name, nameEnd) = DNSUtils.decodeDomainName(byteArray, pos)
        pos = nameEnd + 8
        val rdlen = byteArray[pos++].toInt()
        val cpuLen = byteArray[pos++].toInt()
        val cpu = byteArray.copyOfRange(pos, pos + cpuLen).toString(Charsets.UTF_8)
        pos += cpuLen
        val osLen = byteArray[pos++].toInt()
        val os = byteArray.copyOfRange(pos, pos + osLen).toString(Charsets.UTF_8)
        return HINFORecord(cpu, os, name, ttlInt)
    }


}
package net.cakemc.dns.records

import net.cakemc.dns.types.DNSRecordType
import net.cakemc.dns.units.DNSUtils
import net.cakemc.dns.DnsRecord
import java.nio.ByteBuffer

// A Record (IPv4)
data class ARecord(
    val address: String, // IPv4 address
    val nameInt: String,
    val ttlInt: Int
) : DnsRecord(nameInt, ttlInt, type = DNSRecordType.A) {

    constructor(): this("", "", 0)

    override fun encode(): ByteArray {
        val nameBytes = DNSUtils.encodeDomainName(nameInt)
        val addressBytes = address.split(".").map { it.toInt().toByte() }.toByteArray()
        val buffer = ByteBuffer.allocate(nameBytes.size + 10 + 4) // 10 = type + class + ttl + rdlength
        buffer.put(nameBytes)
        buffer.putShort(DNSRecordType.A.code.toShort())
        buffer.putShort(1) // class IN
        buffer.putInt(ttlInt)
        buffer.putShort(4) // RDLENGTH
        buffer.put(addressBytes)
        return buffer.array()
    }

    override fun decode(byteArray: ByteArray): ARecord {
        var pos = 0
        val (name, nameEnd) = DNSUtils.decodeDomainName(byteArray, pos)
        pos = nameEnd + 8 // skip type (2), class (2), ttl (4)
        val rdlength = ByteBuffer.wrap(byteArray, pos, 2).short.toInt()
        pos += 2
        val ipBytes = byteArray.copyOfRange(pos, pos + rdlength)
        val ip = ipBytes.joinToString(".") { (it.toInt() and 0xFF).toString() }
        return ARecord(ip, name, ttlInt)
    }

}
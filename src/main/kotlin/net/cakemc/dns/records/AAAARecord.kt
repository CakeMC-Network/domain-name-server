package net.cakemc.dns.records

import net.cakemc.dns.types.DNSRecordType
import net.cakemc.dns.units.DNSUtils
import net.cakemc.dns.DnsRecord
import java.net.InetAddress
import java.nio.ByteBuffer

// AAAA Record (IPv6)
data class AAAARecord(
    val address: String, // IPv6 address
    val nameInt: String,
    val ttlInt: Int
) : DnsRecord(nameInt, ttlInt, type = DNSRecordType.AAAA) {

    constructor(): this("", "", 0)

    override fun encode(): ByteArray {
        val nameBytes = DNSUtils.encodeDomainName(nameInt)
        val addressBytes = InetAddress.getByName(address).address // 16 bytes
        val buffer = ByteBuffer.allocate(nameBytes.size + 10 + 16)
        buffer.put(nameBytes)
        buffer.putShort(DNSRecordType.AAAA.code.toShort())
        buffer.putShort(1)
        buffer.putInt(ttlInt)
        buffer.putShort(16)
        buffer.put(addressBytes)
        return buffer.array()
    }

    override fun decode(byteArray: ByteArray): AAAARecord {
        var pos = 0
        val (name, nameEnd) = DNSUtils.decodeDomainName(byteArray, pos)
        pos = nameEnd + 8
        val rdlength = ByteBuffer.wrap(byteArray, pos, 2).short.toInt()
        pos += 2
        val addrBytes = byteArray.copyOfRange(pos, pos + rdlength)
        val ip = InetAddress.getByAddress(addrBytes).hostAddress
        return AAAARecord(ip, name, ttlInt)
    }


}
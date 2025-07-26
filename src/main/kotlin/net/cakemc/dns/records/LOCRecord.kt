package net.cakemc.dns.records

import net.cakemc.dns.types.DNSRecordType
import net.cakemc.dns.units.DNSUtils
import net.cakemc.dns.DnsRecord
import java.nio.ByteBuffer

// LOC Record (RFC 1876)
data class LOCRecord(
    val latitude: String,
    val longitude: String,
    val altitude: Double,
    val size: Double,
    val horizontalPrecision: Double,
    val verticalPrecision: Double,
    val nameInt: String,
    val ttlInt: Int
) : DnsRecord(nameInt, ttlInt, type = DNSRecordType.LOC) {

    constructor(): this("", "", 0.0, 0.0, 0.0, 0.0, "", 0)

    override fun encode(): ByteArray {
        val nameBytes = DNSUtils.encodeDomainName(nameInt)
        val buffer = ByteBuffer.allocate(nameBytes.size + 10 + 16)

        val lat = DNSUtils.encodeLOCPosition(latitude, true)
        val lon = DNSUtils.encodeLOCPosition(longitude, false)
        val alt = ((altitude + 100000.00) * 100.0).toLong()

        buffer.put(nameBytes)
        buffer.putShort(DNSRecordType.LOC.code.toShort())
        buffer.putShort(1)
        buffer.putInt(ttlInt)
        buffer.putShort(16) // RDLENGTH

        buffer.put(0) // version
        buffer.put(DNSUtils.encodeLOCSize(size))
        buffer.put(DNSUtils.encodeLOCSize(horizontalPrecision))
        buffer.put(DNSUtils.encodeLOCSize(verticalPrecision))

        buffer.putInt(lat)
        buffer.putInt(lon)
        buffer.putInt(alt.toInt())

        return buffer.array()
    }

    override fun decode(byteArray: ByteArray): LOCRecord {
        var pos = 0
        val (name, nameEnd) = DNSUtils.decodeDomainName(byteArray, pos)
        pos = nameEnd + 8
        val rdlen = byteArray[pos + 1].toInt()
        pos += 2

        val version = byteArray[pos++]
        val size = DNSUtils.decodeLOCSize(byteArray[pos++])
        val hprec = DNSUtils.decodeLOCSize(byteArray[pos++])
        val vprec = DNSUtils.decodeLOCSize(byteArray[pos++])

        val lat = DNSUtils.decodeLOCPosition(ByteBuffer.wrap(byteArray, pos, 4).int, true)
        pos += 4
        val lon = DNSUtils.decodeLOCPosition(ByteBuffer.wrap(byteArray, pos, 4).int, false)
        pos += 4
        val alt = (ByteBuffer.wrap(byteArray, pos, 4).int.toLong() / 100.0) - 100000.00

        return LOCRecord(lat, lon, alt, size, hprec, vprec, name, ttlInt)
    }


}
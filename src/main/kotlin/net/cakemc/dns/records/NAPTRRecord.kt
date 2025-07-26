package net.cakemc.dns.records

import net.cakemc.dns.types.DNSRecordType
import net.cakemc.dns.units.DNSUtils
import net.cakemc.dns.DnsRecord
import java.nio.ByteBuffer

// NAPTR Record (Naming Authority Pointer)
data class NAPTRRecord(
    val order: Int,
    val preference: Int,
    val flags: String,
    val services: String,
    val regexp: String,
    val replacement: String,
    val nameInt: String,
    val ttlInt: Int
) : DnsRecord(nameInt, ttlInt, type = DNSRecordType.NAPTR) {

    constructor(): this(0, 0, "", "", "", "", "", 0)

    override fun encode(): ByteArray {
        val nameBytes = DNSUtils.encodeDomainName(nameInt)
        val flagsBytes = flags.toByteArray()
        val servicesBytes = services.toByteArray()
        val regexpBytes = regexp.toByteArray()
        val replacementBytes = DNSUtils.encodeDomainName(replacement)

        val rdata =
            ByteBuffer.allocate(2 + 2 + 1 + flagsBytes.size + 1 + servicesBytes.size + 1 + regexpBytes.size + replacementBytes.size)
        rdata.putShort(order.toShort())
        rdata.putShort(preference.toShort())
        rdata.put(flagsBytes.size.toByte())
        rdata.put(flagsBytes)
        rdata.put(servicesBytes.size.toByte())
        rdata.put(servicesBytes)
        rdata.put(regexpBytes.size.toByte())
        rdata.put(regexpBytes)
        rdata.put(replacementBytes)

        val buffer = ByteBuffer.allocate(nameBytes.size + 10 + rdata.capacity())
        buffer.put(nameBytes)
        buffer.putShort(DNSRecordType.NAPTR.code.toShort())
        buffer.putShort(1)
        buffer.putInt(ttlInt)
        buffer.putShort(rdata.capacity().toShort())
        buffer.put(rdata.array())
        return buffer.array()
    }

    override fun decode(byteArray: ByteArray): NAPTRRecord {
        var pos = 0
        val (name, nameEnd) = DNSUtils.decodeDomainName(byteArray, pos)
        pos = nameEnd + 8
        val rdlength = ByteBuffer.wrap(byteArray, pos, 2).short.toInt()
        pos += 2

        val order = ByteBuffer.wrap(byteArray, pos, 2).short.toInt(); pos += 2
        val preference = ByteBuffer.wrap(byteArray, pos, 2).short.toInt(); pos += 2

        val flagsLen = byteArray[pos++].toInt()
        val flags = byteArray.copyOfRange(pos, pos + flagsLen).toString(Charsets.UTF_8); pos += flagsLen

        val servicesLen = byteArray[pos++].toInt()
        val services = byteArray.copyOfRange(pos, pos + servicesLen).toString(Charsets.UTF_8); pos += servicesLen

        val regexpLen = byteArray[pos++].toInt()
        val regexp = byteArray.copyOfRange(pos, pos + regexpLen).toString(Charsets.UTF_8); pos += regexpLen

        val (replacement, _) = DNSUtils.decodeDomainName(byteArray, pos)

        return NAPTRRecord(order, preference, flags, services, regexp, replacement, name, ttlInt)
    }

}
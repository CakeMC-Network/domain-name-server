package net.cakemc.dns.records

import net.cakemc.dns.types.DNSRecordType
import net.cakemc.dns.units.DNSUtils
import net.cakemc.dns.DnsRecord
import java.nio.ByteBuffer

// SVCB Record (RFC 9460)
data class SVCBRecord(
    val priority: Int,
    val targetName: String,
    val params: Map<String, String>,
    val nameInt: String,
    val ttlInt: Int
) : DnsRecord(nameInt, ttlInt, type = DNSRecordType.SVCB) {

    constructor(): this(0, "", emptyMap(), "", 0)

    override fun decode(byteArray: ByteArray): SVCBRecord {
        var pos = 0
        val (name, nameEnd) = DNSUtils.decodeDomainName(byteArray, pos)
        pos = nameEnd
        pos += 2 + 2 + 4 // type, class, ttl
        val rdlen = ByteBuffer.wrap(byteArray, pos, 2).short.toInt()
        pos += 2

        val priority = ByteBuffer.wrap(byteArray, pos, 2).short.toInt()
        pos += 2

        val (target, targetEnd) = DNSUtils.decodeDomainName(byteArray, pos)
        pos = targetEnd

        val params = mutableMapOf<String, String>()
        val rdataEnd = pos + rdlen - 2 - (targetEnd - nameEnd)

        while (pos < rdataEnd) {
            val key = ByteBuffer.wrap(byteArray, pos, 2).short.toInt(); pos += 2
            val len = ByteBuffer.wrap(byteArray, pos, 2).short.toInt(); pos += 2
            val value = byteArray.copyOfRange(pos, pos + len); pos += len
            params[DNSUtils.mapSvcParamCodeToKey(key)] = DNSUtils.decodeSvcParamValue(key, value)
        }

        return SVCBRecord(priority, target, params, name, ttlInt)
    }


    override fun encode(): ByteArray {
        val nameBytes = DNSUtils.encodeDomainName(nameInt)
        val targetNameBytes = DNSUtils.encodeDomainName(targetName)

        val paramBytes = params.entries.flatMap { (key, value) ->
            val keyId = DNSUtils.mapSvcParamKeyToCode(key)
            val valueBytes = DNSUtils.encodeSvcParamValue(key, value)
            val buffer = ByteBuffer.allocate(4 + valueBytes.size)
            buffer.putShort(keyId.toShort())
            buffer.putShort(valueBytes.size.toShort())
            buffer.put(valueBytes)
            buffer.array().toList()
        }.toByteArray()

        val rdataBuffer = ByteBuffer.allocate(2 + targetNameBytes.size + paramBytes.size)
        rdataBuffer.putShort(priority.toShort())
        rdataBuffer.put(targetNameBytes)
        rdataBuffer.put(paramBytes)

        val rdata = rdataBuffer.array()

        val finalBuffer = ByteBuffer.allocate(nameBytes.size + 10 + rdata.size)
        finalBuffer.put(nameBytes)
        finalBuffer.putShort(type.code.toShort())
        finalBuffer.putShort(1) // CLASS: IN
        finalBuffer.putInt(ttlInt)
        finalBuffer.putShort(rdata.size.toShort())
        finalBuffer.put(rdata)

        return finalBuffer.array()
    }


}
// DnsRecords.kt

package net.cakemc.dns

import net.cakemc.dns.DNSUtils.byteArrayToHex
import net.cakemc.dns.DNSUtils.decodeDomainName
import net.cakemc.dns.DNSUtils.decodeLOCPosition
import net.cakemc.dns.DNSUtils.decodeLOCSize
import net.cakemc.dns.DNSUtils.decodeSvcParamValue
import net.cakemc.dns.DNSUtils.encodeDomainName
import net.cakemc.dns.DNSUtils.encodeLOCPosition
import net.cakemc.dns.DNSUtils.encodeLOCSize
import net.cakemc.dns.DNSUtils.encodeSvcParamValue
import net.cakemc.dns.DNSUtils.hexStringToByteArray
import net.cakemc.dns.DNSUtils.mapSvcParamCodeToKey
import net.cakemc.dns.DNSUtils.mapSvcParamKeyToCode
import java.net.InetAddress
import java.nio.ByteBuffer
import java.time.LocalDateTime
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import java.util.*

// Common DNS record base class
abstract class DnsRecord(
    val name: String,
    val ttl: Int,
    val recordClass: DNSClass = DNSClass.IN, // Internet class
    val type: DNSRecordType
) {

    abstract fun decode(byteArray: ByteArray): DnsRecord
    abstract fun encode(): ByteArray

}

// A Record (IPv4)
data class ARecord(
    val address: String, // IPv4 address
    val nameInt: String,
    val ttlInt: Int
) : DnsRecord(nameInt, ttlInt, type = DNSRecordType.A) {

    constructor(): this("", "", 0)

    override fun encode(): ByteArray {
        val nameBytes = encodeDomainName(nameInt)
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
        val (name, nameEnd) = decodeDomainName(byteArray, pos)
        pos = nameEnd + 8 // skip type (2), class (2), ttl (4)
        val rdlength = ByteBuffer.wrap(byteArray, pos, 2).short.toInt()
        pos += 2
        val ipBytes = byteArray.copyOfRange(pos, pos + rdlength)
        val ip = ipBytes.joinToString(".") { (it.toInt() and 0xFF).toString() }
        return ARecord(ip, name, ttlInt)
    }

}

// AAAA Record (IPv6)
data class AAAARecord(
    val address: String, // IPv6 address
    val nameInt: String,
    val ttlInt: Int
) : DnsRecord(nameInt, ttlInt, type = DNSRecordType.AAAA) {

    constructor(): this("", "", 0)

    override fun encode(): ByteArray {
        val nameBytes = encodeDomainName(nameInt)
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
        val (name, nameEnd) = decodeDomainName(byteArray, pos)
        pos = nameEnd + 8
        val rdlength = ByteBuffer.wrap(byteArray, pos, 2).short.toInt()
        pos += 2
        val addrBytes = byteArray.copyOfRange(pos, pos + rdlength)
        val ip = InetAddress.getByAddress(addrBytes).hostAddress
        return AAAARecord(ip, name, ttlInt)
    }


}

// CNAME Record (Canonical Name)
data class CNAMERecord(
    val canonicalName: String,
    val nameInt: String,
    val ttlInt: Int
) : DnsRecord(nameInt, ttlInt, type = DNSRecordType.CNAME) {

    constructor(): this("", "", 0)

    override fun encode(): ByteArray {
        val nameBytes = encodeDomainName(nameInt)
        val cnameBytes = encodeDomainName(canonicalName)
        val buffer = ByteBuffer.allocate(nameBytes.size + 10 + cnameBytes.size)
        buffer.put(nameBytes)
        buffer.putShort(DNSRecordType.CNAME.code.toShort())
        buffer.putShort(1)
        buffer.putInt(ttlInt)
        buffer.putShort(cnameBytes.size.toShort())
        buffer.put(cnameBytes)
        return buffer.array()
    }

    override fun decode(byteArray: ByteArray): CNAMERecord {
        var pos = 0
        val (name, nameEnd) = decodeDomainName(byteArray, pos)
        pos = nameEnd + 8
        val rdlength = ByteBuffer.wrap(byteArray, pos, 2).short.toInt()
        pos += 2
        val (cname, _) = decodeDomainName(byteArray, pos)
        return CNAMERecord(cname, name, ttlInt)
    }

}

// MX Record (Mail Exchange)
data class MXRecord(
    val preference: Int,
    val exchange: String,
    val nameInt: String,
    val ttlInt: Int
) : DnsRecord(nameInt, ttlInt, type = DNSRecordType.MX) {

    constructor(): this(0, "", "", 0)

    override fun encode(): ByteArray {
        val nameBytes = encodeDomainName(nameInt)
        val exchangeBytes = encodeDomainName(exchange)
        val buffer = ByteBuffer.allocate(nameBytes.size + 10 + 2 + exchangeBytes.size)
        buffer.put(nameBytes)
        buffer.putShort(DNSRecordType.MX.code.toShort())
        buffer.putShort(1)
        buffer.putInt(ttlInt)
        buffer.putShort((2 + exchangeBytes.size).toShort())
        buffer.putShort(preference.toShort())
        buffer.put(exchangeBytes)
        return buffer.array()
    }

    override fun decode(byteArray: ByteArray): MXRecord {
        var pos = 0
        val (name, nameEnd) = decodeDomainName(byteArray, pos)
        pos = nameEnd + 8
        val rdlength = ByteBuffer.wrap(byteArray, pos, 2).short.toInt()
        pos += 2
        val pref = ByteBuffer.wrap(byteArray, pos, 2).short.toInt()
        pos += 2
        val (exch, _) = decodeDomainName(byteArray, pos)
        return MXRecord(pref, exch, name, ttlInt)
    }


}

// NS Record (Name Server)
data class NSRecord(
    val nsdName: String, // Authoritative nameserver
    val nameInt: String,
    val ttlInt: Int
) : DnsRecord(nameInt, ttlInt, type = DNSRecordType.NS) {

    constructor(): this("", "", 0)

    override fun encode(): ByteArray {
        val nameBytes = encodeDomainName(nameInt)
        val nsBytes = encodeDomainName(nsdName)
        val buffer = ByteBuffer.allocate(nameBytes.size + 10 + nsBytes.size)
        buffer.put(nameBytes)
        buffer.putShort(DNSRecordType.NS.code.toShort())
        buffer.putShort(1)
        buffer.putInt(ttlInt)
        buffer.putShort(nsBytes.size.toShort())
        buffer.put(nsBytes)
        return buffer.array()
    }

    override fun decode(byteArray: ByteArray): NSRecord {
        var pos = 0
        val (name, nameEnd) = decodeDomainName(byteArray, pos)
        pos = nameEnd + 8
        val rdlength = ByteBuffer.wrap(byteArray, pos, 2).short.toInt()
        pos += 2
        val (nsd, _) = decodeDomainName(byteArray, pos)
        return NSRecord(nsd, name, ttlInt)
    }


}

// TXT Record (Text)
data class TXTRecord(
    val texts: List<String>,
    val nameInt: String,
    val ttlInt: Int
) : DnsRecord(nameInt, ttlInt, type = DNSRecordType.TXT) {

    constructor(): this(emptyList(), "", 0)

    override fun encode(): ByteArray {
        val nameBytes = encodeDomainName(nameInt)
        val txtBytes = texts.flatMap { str ->
            val strBytes = str.toByteArray()
            listOf(strBytes.size.toByte()) + strBytes.toList()
        }.toByteArray()
        val buffer = ByteBuffer.allocate(nameBytes.size + 10 + txtBytes.size)
        buffer.put(nameBytes)
        buffer.putShort(DNSRecordType.TXT.code.toShort())
        buffer.putShort(1)
        buffer.putInt(ttlInt)
        buffer.putShort(txtBytes.size.toShort())
        buffer.put(txtBytes)
        return buffer.array()
    }

    override fun decode(byteArray: ByteArray): TXTRecord {
        var pos = 0
        val (name, nameEnd) = decodeDomainName(byteArray, pos)
        pos = nameEnd + 8
        val rdlength = ByteBuffer.wrap(byteArray, pos, 2).short.toInt()
        pos += 2
        val texts = mutableListOf<String>()
        val end = pos + rdlength
        while (pos < end) {
            val len = byteArray[pos].toInt()
            pos++
            val str = byteArray.copyOfRange(pos, pos + len).toString(Charsets.UTF_8)
            texts.add(str)
            pos += len
        }
        return TXTRecord(texts, name, ttlInt)
    }


}

// SRV Record (Service Locator)
data class SRVRecord(
    val priority: Int,
    val weight: Int,
    val port: Int,
    val target: String,
    val nameInt: String,
    val ttlInt: Int
) : DnsRecord(nameInt, ttlInt, type = DNSRecordType.SRV) {

    constructor(): this(0, 0, 0, "", "", 0)

    override fun encode(): ByteArray {
        val nameBytes = encodeDomainName(nameInt)
        val targetBytes = encodeDomainName(target)
        val rdataLen = 6 + targetBytes.size
        val buffer = ByteBuffer.allocate(nameBytes.size + 10 + rdataLen)
        buffer.put(nameBytes)
        buffer.putShort(DNSRecordType.SRV.code.toShort())
        buffer.putShort(1)
        buffer.putInt(ttlInt)
        buffer.putShort(rdataLen.toShort())
        buffer.putShort(priority.toShort())
        buffer.putShort(weight.toShort())
        buffer.putShort(port.toShort())
        buffer.put(targetBytes)
        return buffer.array()
    }

    override fun decode(byteArray: ByteArray): SRVRecord {
        var pos = 0
        val (name, nameEnd) = decodeDomainName(byteArray, pos)
        pos = nameEnd + 8
        val rdlength = ByteBuffer.wrap(byteArray, pos, 2).short.toInt()
        pos += 2
        val prio = ByteBuffer.wrap(byteArray, pos, 2).short.toInt()
        val weight = ByteBuffer.wrap(byteArray, pos + 2, 2).short.toInt()
        val port = ByteBuffer.wrap(byteArray, pos + 4, 2).short.toInt()
        pos += 6
        val (target, _) = decodeDomainName(byteArray, pos)
        return SRVRecord(prio, weight, port, target, name, ttlInt)
    }


}

// PTR Record (Pointer - Reverse DNS)
data class PTRRecord(
    val ptrDomainName: String,
    val nameInt: String,
    val ttlInt: Int
) : DnsRecord(nameInt, ttlInt, type = DNSRecordType.PTR) {

    constructor(): this("", "", 0)

    override fun encode(): ByteArray {
        val nameBytes = encodeDomainName(nameInt)
        val ptrBytes = encodeDomainName(ptrDomainName)
        val buffer = ByteBuffer.allocate(nameBytes.size + 10 + ptrBytes.size)
        buffer.put(nameBytes)
        buffer.putShort(DNSRecordType.PTR.code.toShort())
        buffer.putShort(1) // class IN
        buffer.putInt(ttlInt)
        buffer.putShort(ptrBytes.size.toShort())
        buffer.put(ptrBytes)
        return buffer.array()
    }

    override fun decode(byteArray: ByteArray): PTRRecord {
        var pos = 0
        val (name, nameEnd) = decodeDomainName(byteArray, pos)
        pos = nameEnd + 8
        val rdlength = ByteBuffer.wrap(byteArray, pos, 2).short.toInt()
        pos += 2
        val (ptr, _) = decodeDomainName(byteArray, pos)
        return PTRRecord(ptr, name, ttlInt)
    }


}

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
        val nameBytes = encodeDomainName(nameInt)
        val mNameBytes = encodeDomainName(mName)
        val rNameBytes = encodeDomainName(rName)
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
        val (name, nameEnd) = decodeDomainName(byteArray, pos)
        pos = nameEnd + 8
        val rdlength = ByteBuffer.wrap(byteArray, pos, 2).short.toInt()
        pos += 2
        val (mName, mEnd) = decodeDomainName(byteArray, pos)
        val (rName, rEnd) = decodeDomainName(byteArray, mEnd)
        val buffer = ByteBuffer.wrap(byteArray, rEnd, 20)
        return SOARecord(
            mName, rName,
            buffer.int.toLong(), buffer.int.toLong(), buffer.int.toLong(),
            buffer.int.toLong(), buffer.int.toLong(), name, ttlInt
        )
    }


}

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
        val nameBytes = encodeDomainName(nameInt)
        val flagsBytes = flags.toByteArray()
        val servicesBytes = services.toByteArray()
        val regexpBytes = regexp.toByteArray()
        val replacementBytes = encodeDomainName(replacement)

        val rdata = ByteBuffer.allocate(2 + 2 + 1 + flagsBytes.size + 1 + servicesBytes.size + 1 + regexpBytes.size + replacementBytes.size)
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
        val (name, nameEnd) = decodeDomainName(byteArray, pos)
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

        val (replacement, _) = decodeDomainName(byteArray, pos)

        return NAPTRRecord(order, preference, flags, services, regexp, replacement, name, ttlInt)
    }

}

// CAA Record (Certification Authority Authorization)
data class CAARecord(
    val flag: Int,
    val tag: String,        // e.g., issue, issuewild, iodef
    val value: String,
    val nameInt: String,
    val ttlInt: Int
) : DnsRecord(nameInt, ttlInt, type = DNSRecordType.CAA) {


    constructor(): this(0, "", "", "", 0)

    override fun encode(): ByteArray {
        val nameBytes = encodeDomainName(nameInt)
        val tagBytes = tag.toByteArray()
        val valueBytes = value.toByteArray()
        val rdataLen = 1 + 1 + tagBytes.size + valueBytes.size

        val buffer = ByteBuffer.allocate(nameBytes.size + 10 + rdataLen)
        buffer.put(nameBytes)
        buffer.putShort(DNSRecordType.CAA.code.toShort())
        buffer.putShort(1)
        buffer.putInt(ttlInt)
        buffer.putShort(rdataLen.toShort())
        buffer.put(flag.toByte())
        buffer.put(tagBytes.size.toByte())
        buffer.put(tagBytes)
        buffer.put(valueBytes)
        return buffer.array()
    }

    override fun decode(byteArray: ByteArray): CAARecord {
        var pos = 0
        val (name, nameEnd) = decodeDomainName(byteArray, pos)
        pos = nameEnd + 8
        val rdlength = ByteBuffer.wrap(byteArray, pos, 2).short.toInt(); pos += 2

        val flag = byteArray[pos++].toInt()
        val tagLen = byteArray[pos++].toInt()
        val tag = byteArray.copyOfRange(pos, pos + tagLen).toString(Charsets.UTF_8); pos += tagLen
        val value = byteArray.copyOfRange(pos, pos + (rdlength - 2 - tagLen)).toString(Charsets.UTF_8)

        return CAARecord(flag, tag, value, name, ttlInt)
    }


}

// DNSKEY Record (DNSSEC Public Key)
data class DNSKEYRecord(
    val flags: Int,
    val protocol: Int,
    val algorithm: Int,
    val publicKey: String,
    val nameInt: String,
    val ttlInt: Int
) : DnsRecord(nameInt, ttlInt, type = DNSRecordType.DNSKEY) {

    constructor(): this(0, 0, 0, "", "", 0)

    override fun encode(): ByteArray {
        val nameBytes = encodeDomainName(nameInt)
        val pubKeyBytes = Base64.getDecoder().decode(publicKey)
        val rdataLen = 4 + pubKeyBytes.size

        val buffer = ByteBuffer.allocate(nameBytes.size + 10 + rdataLen)
        buffer.put(nameBytes)
        buffer.putShort(DNSRecordType.DNSKEY.code.toShort())
        buffer.putShort(1)
        buffer.putInt(ttlInt)
        buffer.putShort(rdataLen.toShort())
        buffer.putShort(flags.toShort())
        buffer.put(protocol.toByte())
        buffer.put(algorithm.toByte())
        buffer.put(pubKeyBytes)
        return buffer.array()
    }

    override fun decode(byteArray: ByteArray): DNSKEYRecord {
        var pos = 0
        val (name, nameEnd) = decodeDomainName(byteArray, pos)
        pos = nameEnd + 8
        val rdlength = ByteBuffer.wrap(byteArray, pos, 2).short.toInt(); pos += 2

        val flags = ByteBuffer.wrap(byteArray, pos, 2).short.toInt(); pos += 2
        val protocol = byteArray[pos++].toInt()
        val algorithm = byteArray[pos++].toInt()
        val pubKeyBytes = byteArray.copyOfRange(pos, pos + rdlength - 4)
        val publicKey = Base64.getEncoder().encodeToString(pubKeyBytes)

        return DNSKEYRecord(flags, protocol, algorithm, publicKey, name, ttlInt)
    }


}

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
        val nameBytes = encodeDomainName(nameInt)
        val signerBytes = encodeDomainName(signerName)
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
        val (name, nameEnd) = decodeDomainName(byteArray, pos)
        pos = nameEnd + 8
        val rdlength = ByteBuffer.wrap(byteArray, pos, 2).short.toInt(); pos += 2

        val typeCoveredCode = ByteBuffer.wrap(byteArray, pos, 2).short.toInt(); pos += 2
        val algorithm = byteArray[pos++].toInt()
        val labels = byteArray[pos++].toInt()
        val origTTL = ByteBuffer.wrap(byteArray, pos, 4).int; pos += 4
        val sigExpire = ByteBuffer.wrap(byteArray, pos, 4).int.toString(); pos += 4
        val sigIncept = ByteBuffer.wrap(byteArray, pos, 4).int.toString(); pos += 4
        val keyTag = ByteBuffer.wrap(byteArray, pos, 2).short.toInt(); pos += 2
        val (signer, signerEnd) = decodeDomainName(byteArray, pos)
        val signature = Base64.getEncoder().encodeToString(byteArray.copyOfRange(signerEnd, pos + rdlength))

        return RRSIGRecord(
            typeCovered = DNSRecordType.fromCode(typeCoveredCode).name,
            algorithm, labels, origTTL, sigExpire, sigIncept, keyTag, signer, signature, name, ttlInt
        )
    }

}

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
        val nameBytes = encodeDomainName(nameInt)
        val digestBytes = hexStringToByteArray(digest) // or Base64 if your digest is encoded
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
        val (name, nameEnd) = decodeDomainName(byteArray, pos)
        pos = nameEnd + 8
        val rdlength = ByteBuffer.wrap(byteArray, pos, 2).short.toInt(); pos += 2
        val keyTag = ByteBuffer.wrap(byteArray, pos, 2).short.toInt(); pos += 2
        val algorithm = byteArray[pos++].toInt()
        val digestType = byteArray[pos++].toInt()
        val digestBytes = byteArray.copyOfRange(pos, pos + (rdlength - 4))
        val digest = byteArrayToHex(digestBytes)
        return DSRecord(keyTag, algorithm, digestType, digest, name, ttlInt)
    }


}

// Generic UNKNOWN Record (for future-proofing)
data class UnknownRecord(
    val typeCode: Int,
    val data: String,
    val nameInt: String,
    val ttlInt: Int
) : DnsRecord(nameInt, ttlInt, type = DNSRecordType.Unknown) {

    constructor(): this(0, "", "", 0)

    override fun encode(): ByteArray {
        val nameBytes = encodeDomainName(nameInt)
        val dataBytes = data.toByteArray()
        val buffer = ByteBuffer.allocate(nameBytes.size + 10 + dataBytes.size)
        buffer.put(nameBytes)
        buffer.putShort(typeCode.toShort())
        buffer.putShort(1)
        buffer.putInt(ttlInt)
        buffer.putShort(dataBytes.size.toShort())
        buffer.put(dataBytes)
        return buffer.array()
    }

    override fun decode(byteArray: ByteArray): UnknownRecord {
        var pos = 0
        val (name, nameEnd) = decodeDomainName(byteArray, pos)
        val typeCode = ByteBuffer.wrap(byteArray, nameEnd, 2).short.toInt()
        pos = nameEnd + 8
        val rdlength = ByteBuffer.wrap(byteArray, pos, 2).short.toInt(); pos += 2
        val dataStr = byteArray.copyOfRange(pos, pos + rdlength).toString(Charsets.UTF_8)
        return UnknownRecord(typeCode, dataStr, name, ttlInt)
    }


}

// SPF Record (Deprecated, but still used)
data class SPFRecord(
    val data: String, // SPF policy string (same as TXT, historically separate)
    val nameInt: String,
    val ttlInt: Int
) : DnsRecord(nameInt, ttlInt, type = DNSRecordType.SPF) {

    constructor(): this("", "", 0)

    override fun encode(): ByteArray {
        val nameBytes = encodeDomainName(nameInt)
        val dataBytes = data.toByteArray()
        val txtBytes = byteArrayOf(dataBytes.size.toByte()) + dataBytes
        val buffer = ByteBuffer.allocate(nameBytes.size + 10 + txtBytes.size)
        buffer.put(nameBytes)
        buffer.putShort(DNSRecordType.SPF.code.toShort())
        buffer.putShort(1)
        buffer.putInt(ttlInt)
        buffer.putShort(txtBytes.size.toShort())
        buffer.put(txtBytes)
        return buffer.array()
    }

    override fun decode(byteArray: ByteArray): SPFRecord {
        var pos = 0
        val (name, nameEnd) = decodeDomainName(byteArray, pos)
        pos = nameEnd + 8
        val rdlength = ByteBuffer.wrap(byteArray, pos, 2).short.toInt(); pos += 2
        val txtLen = byteArray[pos++].toInt()
        val str = byteArray.copyOfRange(pos, pos + txtLen).toString(Charsets.UTF_8)
        return SPFRecord(str, name, ttlInt)
    }


}

// URI Record (RFC 7553)
data class URIRecord(
    val priority: Int,
    val weight: Int,
    val target: String, // URI string
    val nameInt: String,
    val ttlInt: Int
) : DnsRecord(nameInt, ttlInt, type = DNSRecordType.URI) {

    constructor(): this(0, 0, "", "", 0)

    override fun encode(): ByteArray {
        val nameBytes = encodeDomainName(nameInt)
        val targetBytes = target.toByteArray()
        val rdataLen = 4 + targetBytes.size
        val buffer = ByteBuffer.allocate(nameBytes.size + 10 + rdataLen)
        buffer.put(nameBytes)
        buffer.putShort(DNSRecordType.URI.code.toShort())
        buffer.putShort(1)
        buffer.putInt(ttlInt)
        buffer.putShort(rdataLen.toShort())
        buffer.putShort(priority.toShort())
        buffer.putShort(weight.toShort())
        buffer.put(targetBytes)
        return buffer.array()
    }

    override fun decode(byteArray: ByteArray): URIRecord {
        var pos = 0
        val (name, nameEnd) = decodeDomainName(byteArray, pos)
        pos = nameEnd + 8
        val rdlength = ByteBuffer.wrap(byteArray, pos, 2).short.toInt(); pos += 2
        val priority = ByteBuffer.wrap(byteArray, pos, 2).short.toInt(); pos += 2
        val weight = ByteBuffer.wrap(byteArray, pos, 2).short.toInt(); pos += 2
        val target = byteArray.copyOfRange(pos, pos + rdlength - 4).toString(Charsets.UTF_8)
        return URIRecord(priority, weight, target, name, ttlInt)
    }


}

// CERT Record (RFC 4398)
data class CERTRecord(
    val certType: Int,
    val keyTag: Int,
    val algorithm: Int,
    val certificate: String,
    val nameInt: String,
    val ttlInt: Int
) : DnsRecord(nameInt, ttlInt, type = DNSRecordType.CERT) {

    constructor(): this(0, 0, 0, "", "", 0)

    override fun encode(): ByteArray {
        val nameBytes = encodeDomainName(nameInt)
        val certBytes = Base64.getDecoder().decode(certificate)
        val rdataLen = 5 + certBytes.size
        val buffer = ByteBuffer.allocate(nameBytes.size + 10 + rdataLen)
        buffer.put(nameBytes)
        buffer.putShort(DNSRecordType.CERT.code.toShort())
        buffer.putShort(1)
        buffer.putInt(ttlInt)
        buffer.putShort(rdataLen.toShort())
        buffer.putShort(certType.toShort())
        buffer.putShort(keyTag.toShort())
        buffer.put(algorithm.toByte())
        buffer.put(certBytes)
        return buffer.array()
    }

    override fun decode(byteArray: ByteArray): CERTRecord {
        var pos = 0
        val (name, nameEnd) = decodeDomainName(byteArray, pos)
        pos = nameEnd + 8
        val rdlength = ByteBuffer.wrap(byteArray, pos, 2).short.toInt(); pos += 2
        val certType = ByteBuffer.wrap(byteArray, pos, 2).short.toInt(); pos += 2
        val keyTag = ByteBuffer.wrap(byteArray, pos, 2).short.toInt(); pos += 2
        val algorithm = byteArray[pos++].toInt()
        val certBytes = byteArray.copyOfRange(pos, pos + rdlength - 5)
        val certStr = Base64.getEncoder().encodeToString(certBytes)
        return CERTRecord(certType, keyTag, algorithm, certStr, name, ttlInt)
    }

}

// TLSA Record (RFC 6698)
data class TLSARecord(
    val usage: Int,
    val selector: Int,
    val matchingType: Int,
    val certificateAssociationData: String,
    val nameInt: String,
    val ttlInt: Int
) : DnsRecord(nameInt, ttlInt, type = DNSRecordType.TLSA) {

    constructor(): this(0, 0, 0, "", "", 0)

    override fun encode(): ByteArray {
        val nameBytes = encodeDomainName(nameInt)
        val certBytes = Base64.getDecoder().decode(certificateAssociationData)
        val rdataLen = 3 + certBytes.size
        val buffer = ByteBuffer.allocate(nameBytes.size + 10 + rdataLen)
        buffer.put(nameBytes)
        buffer.putShort(DNSRecordType.TLSA.code.toShort())
        buffer.putShort(1)
        buffer.putInt(ttlInt)
        buffer.putShort(rdataLen.toShort())
        buffer.put(usage.toByte())
        buffer.put(selector.toByte())
        buffer.put(matchingType.toByte())
        buffer.put(certBytes)
        return buffer.array()
    }

    override fun decode(byteArray: ByteArray): TLSARecord {
        var pos = 0
        val (name, nameEnd) = decodeDomainName(byteArray, pos)
        pos = nameEnd + 8
        val rdlength = ByteBuffer.wrap(byteArray, pos, 2).short.toInt(); pos += 2
        val usage = byteArray[pos++].toInt()
        val selector = byteArray[pos++].toInt()
        val matchingType = byteArray[pos++].toInt()
        val certBytes = byteArray.copyOfRange(pos, pos + rdlength - 3)
        val certStr = Base64.getEncoder().encodeToString(certBytes)
        return TLSARecord(usage, selector, matchingType, certStr, name, ttlInt)
    }


}

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
        val nameBytes = encodeDomainName(nameInt)
        val buffer = ByteBuffer.allocate(nameBytes.size + 10 + 16)

        val lat = encodeLOCPosition(latitude, true)
        val lon = encodeLOCPosition(longitude, false)
        val alt = ((altitude + 100000.00) * 100.0).toLong()

        buffer.put(nameBytes)
        buffer.putShort(DNSRecordType.LOC.code.toShort())
        buffer.putShort(1)
        buffer.putInt(ttlInt)
        buffer.putShort(16) // RDLENGTH

        buffer.put(0) // version
        buffer.put(encodeLOCSize(size))
        buffer.put(encodeLOCSize(horizontalPrecision))
        buffer.put(encodeLOCSize(verticalPrecision))

        buffer.putInt(lat)
        buffer.putInt(lon)
        buffer.putInt(alt.toInt())

        return buffer.array()
    }

    override fun decode(byteArray: ByteArray): LOCRecord {
        var pos = 0
        val (name, nameEnd) = decodeDomainName(byteArray, pos)
        pos = nameEnd + 8
        val rdlen = byteArray[pos + 1].toInt()
        pos += 2

        val version = byteArray[pos++]
        val size = decodeLOCSize(byteArray[pos++])
        val hprec = decodeLOCSize(byteArray[pos++])
        val vprec = decodeLOCSize(byteArray[pos++])

        val lat = decodeLOCPosition(ByteBuffer.wrap(byteArray, pos, 4).int, true)
        pos += 4
        val lon = decodeLOCPosition(ByteBuffer.wrap(byteArray, pos, 4).int, false)
        pos += 4
        val alt = (ByteBuffer.wrap(byteArray, pos, 4).int.toLong() / 100.0) - 100000.00

        return LOCRecord(lat, lon, alt, size, hprec, vprec, name, ttlInt)
    }


}

// HINFO Record (RFC 8482)
data class HINFORecord(
    val cpu: String,
    val os: String,
    val nameInt: String,
    val ttlInt: Int
) : DnsRecord(nameInt, ttlInt, type = DNSRecordType.HINFO) {

    constructor(): this("", "", "", 0)

    override fun encode(): ByteArray {
        val nameBytes = encodeDomainName(nameInt)
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
        val (name, nameEnd) = decodeDomainName(byteArray, pos)
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

// APL Record (RFC 3123)
data class APLRecord(
    val addressFamily: Int, // e.g., 1 = IPv4, 2 = IPv6
    val prefix: String,
    val negation: Boolean,
    val nameInt: String,
    val ttlInt: Int
) : DnsRecord(nameInt, ttlInt, type = DNSRecordType.APL) {

    constructor(): this(0, "", false, "", 0)

    override fun encode(): ByteArray {
        val nameBytes = encodeDomainName(nameInt)
        val prefixBytes = InetAddress.getByName(prefix).address
        val length = prefixBytes.size
        val flagLength = (if (negation) 0x80 else 0x00) or length
        val rdata = ByteBuffer.allocate(4 + length)
        rdata.putShort(addressFamily.toShort())
        rdata.put(prefix.split("/")[1].toInt().toByte()) // prefix length
        rdata.put(flagLength.toByte())
        rdata.put(prefixBytes)
        val rdataArr = rdata.array()
        val buffer = ByteBuffer.allocate(nameBytes.size + 10 + rdataArr.size)
        buffer.put(nameBytes)
        buffer.putShort(DNSRecordType.APL.code.toShort())
        buffer.putShort(1)
        buffer.putInt(ttlInt)
        buffer.putShort(rdataArr.size.toShort())
        buffer.put(rdataArr)
        return buffer.array()
    }

    override fun decode(byteArray: ByteArray): APLRecord {
        var pos = 0
        val (name, nameEnd) = decodeDomainName(byteArray, pos)
        pos = nameEnd + 8
        val rdlen = ByteBuffer.wrap(byteArray, pos, 2).short.toInt()
        pos += 2
        val family = ByteBuffer.wrap(byteArray, pos, 2).short.toInt(); pos += 2
        val prefixLen = byteArray[pos++].toInt()
        val flagsLength = byteArray[pos++].toInt()
        val neg = (flagsLength and 0x80) != 0
        val addrLen = flagsLength and 0x7F
        val addrBytes = byteArray.copyOfRange(pos, pos + addrLen)
        val addrStr = InetAddress.getByAddress(addrBytes).hostAddress
        val prefixStr = "$addrStr/$prefixLen"
        return APLRecord(family, prefixStr, neg, name, ttlInt)
    }


}

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
        val nameBytes = encodeDomainName(nameInt)
        val fpBytes = hexStringToByteArray(fingerprint)
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
        val (name, nameEnd) = decodeDomainName(byteArray, pos)
        pos = nameEnd + 8
        val rdlen = ByteBuffer.wrap(byteArray, pos, 2).short.toInt(); pos += 2
        val algorithm = byteArray[pos++].toInt()
        val fpType = byteArray[pos++].toInt()
        val fp = byteArray.copyOfRange(pos, pos + rdlen - 2)
        return SSHFPRecord(algorithm, fpType, byteArrayToHex(fp), name, ttlInt)
    }


}

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
        val (name, nameEnd) = decodeDomainName(byteArray, pos)
        pos = nameEnd
        pos += 2 + 2 + 4 // type, class, ttl
        val rdlen = ByteBuffer.wrap(byteArray, pos, 2).short.toInt()
        pos += 2

        val priority = ByteBuffer.wrap(byteArray, pos, 2).short.toInt()
        pos += 2

        val (target, targetEnd) = decodeDomainName(byteArray, pos)
        pos = targetEnd

        val params = mutableMapOf<String, String>()
        val rdataEnd = pos + rdlen - 2 - (targetEnd - nameEnd)

        while (pos < rdataEnd) {
            val key = ByteBuffer.wrap(byteArray, pos, 2).short.toInt(); pos += 2
            val len = ByteBuffer.wrap(byteArray, pos, 2).short.toInt(); pos += 2
            val value = byteArray.copyOfRange(pos, pos + len); pos += len
            params[mapSvcParamCodeToKey(key)] = decodeSvcParamValue(key, value)
        }

        return SVCBRecord(priority, target, params, name, ttlInt)
    }


    override fun encode(): ByteArray {
        val nameBytes = encodeDomainName(nameInt)
        val targetNameBytes = encodeDomainName(targetName)

        val paramBytes = params.entries.flatMap { (key, value) ->
            val keyId = mapSvcParamKeyToCode(key)
            val valueBytes = encodeSvcParamValue(key, value)
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

// HTTPS Record (RFC 9460 — special case of SVCB)
data class HTTPSRecord(
    val priority: Int,
    val targetName: String,
    val params: Map<String, String>,
    val nameInt: String,
    val ttlInt: Int
) : DnsRecord(nameInt, ttlInt, type = DNSRecordType.HTTPS) {

    constructor(): this(0, "", emptyMap(), "", 0)

    override fun encode(): ByteArray = SVCBRecord(priority, targetName, params, nameInt, ttlInt).encode()

    override fun decode(byteArray: ByteArray): HTTPSRecord {
        val svcb = SVCBRecord(0, "", emptyMap(), nameInt, ttlInt).decode(byteArray)
        return HTTPSRecord(svcb.priority, svcb.targetName, svcb.params, svcb.nameInt, svcb.ttlInt)
    }

}

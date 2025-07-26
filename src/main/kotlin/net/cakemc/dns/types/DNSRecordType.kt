package net.cakemc.dns.types

import net.cakemc.dns.DnsRecord
import net.cakemc.dns.records.*
import kotlin.reflect.KClass

enum class DNSRecordType(val code: Int, val recordClass: KClass<out DnsRecord>) {
    A(1, ARecord::class),
    NS(2, NSRecord::class),
    CNAME(5, CNAMERecord::class),
    SOA(6, SOARecord::class),
    PTR(12, PTRRecord::class),
    HINFO(13, HINFORecord::class),
    MX(15, MXRecord::class),
    TXT(16, TXTRecord::class),
    AAAA(28, AAAARecord::class),
    LOC(29, LOCRecord::class),
    SRV(33, SRVRecord::class),
    NAPTR(35, NAPTRRecord::class),
    CERT(37, CERTRecord::class),
    APL(42, APLRecord::class),
    DS(43, DSRecord::class),
    SSHFP(44, SSHFPRecord::class),
    RRSIG(46, RRSIGRecord::class),
    DNSKEY(48, DNSKEYRecord::class),
    TLSA(52, TLSARecord::class),
    SVCB(64, SVCBRecord::class),
    HTTPS(65, HTTPSRecord::class),
    SPF(99, SPFRecord::class),
    URI(256, URIRecord::class),
    CAA(257, CAARecord::class),
    Unknown(-1, UnknownRecord::class);

    companion object {
        private val map = values().associateBy(DNSRecordType::code)
        fun fromCode(code: Int): DNSRecordType = map[code] ?: Unknown


    }

    fun construct(): DnsRecord {
        return try {
            recordClass.java.getConstructor().newInstance()
        } catch (e: Exception) {
            throw IllegalStateException("Could not instantiate record for type $name", e)
        }
    }
}

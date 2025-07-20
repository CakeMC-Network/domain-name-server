// DnsRecords.kt

package net.cakemc.dns

// Common DNS record base class
open class DnsRecord(
    val name: String,
    val ttl: Int,
    val recordClass: String = "IN" // Internet class
)

// A Record (IPv4)
data class ARecord(
    val address: String, // IPv4 address
    val nameInt: String,
    val ttlInt: Int
) : DnsRecord(nameInt, ttlInt)

// AAAA Record (IPv6)
data class AAAARecord(
    val address: String, // IPv6 address
    val nameInt: String,
    val ttlInt: Int
) : DnsRecord(nameInt, ttlInt)

// CNAME Record (Canonical Name)
data class CNAMERecord(
    val canonicalName: String,
    val nameInt: String,
    val ttlInt: Int
) : DnsRecord(nameInt, ttlInt)

// MX Record (Mail Exchange)
data class MXRecord(
    val preference: Int,
    val exchange: String,
    val nameInt: String,
    val ttlInt: Int
) : DnsRecord(nameInt, ttlInt)

// NS Record (Name Server)
data class NSRecord(
    val nsdName: String, // Authoritative nameserver
    val nameInt: String,
    val ttlInt: Int
) : DnsRecord(nameInt, ttlInt)

// TXT Record (Text)
data class TXTRecord(
    val texts: List<String>,
    val nameInt: String,
    val ttlInt: Int
) : DnsRecord(nameInt, ttlInt)

// SRV Record (Service Locator)
data class SRVRecord(
    val priority: Int,
    val weight: Int,
    val port: Int,
    val target: String,
    val nameInt: String,
    val ttlInt: Int
) : DnsRecord(nameInt, ttlInt)

// PTR Record (Pointer - Reverse DNS)
data class PTRRecord(
    val ptrDomainName: String,
    val nameInt: String,
    val ttlInt: Int
) : DnsRecord(nameInt, ttlInt)

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
) : DnsRecord(nameInt, ttlInt)

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
) : DnsRecord(nameInt, ttlInt)

// CAA Record (Certification Authority Authorization)
data class CAARecord(
    val flag: Int,
    val tag: String,        // e.g., issue, issuewild, iodef
    val value: String,
    val nameInt: String,
    val ttlInt: Int
) : DnsRecord(nameInt, ttlInt)

// DNSKEY Record (DNSSEC Public Key)
data class DNSKEYRecord(
    val flags: Int,
    val protocol: Int,
    val algorithm: Int,
    val publicKey: String,
    val nameInt: String,
    val ttlInt: Int
) : DnsRecord(nameInt, ttlInt)

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
) : DnsRecord(nameInt, ttlInt)

// DS Record (Delegation Signer)
data class DSRecord(
    val keyTag: Int,
    val algorithm: Int,
    val digestType: Int,
    val digest: String,
    val nameInt: String,
    val ttlInt: Int
) : DnsRecord(nameInt, ttlInt)

// Generic UNKNOWN Record (for future-proofing)
data class UnknownRecord(
    val typeCode: Int,
    val data: String,
    val nameInt: String,
    val ttlInt: Int
) : DnsRecord(nameInt, ttlInt)

// SPF Record (Deprecated, but still used)
data class SPFRecord(
    val data: String, // SPF policy string (same as TXT, historically separate)
    val nameInt: String,
    val ttlInt: Int
) : DnsRecord(nameInt, ttlInt)

// URI Record (RFC 7553)
data class URIRecord(
    val priority: Int,
    val weight: Int,
    val target: String, // URI string
    val nameInt: String,
    val ttlInt: Int
) : DnsRecord(nameInt, ttlInt)

// CERT Record (RFC 4398)
data class CERTRecord(
    val certType: Int,
    val keyTag: Int,
    val algorithm: Int,
    val certificate: String,
    val nameInt: String,
    val ttlInt: Int
) : DnsRecord(nameInt, ttlInt)

// TLSA Record (RFC 6698)
data class TLSARecord(
    val usage: Int,
    val selector: Int,
    val matchingType: Int,
    val certificateAssociationData: String,
    val nameInt: String,
    val ttlInt: Int
) : DnsRecord(nameInt, ttlInt)

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
) : DnsRecord(nameInt, ttlInt)

// HINFO Record (RFC 8482)
data class HINFORecord(
    val cpu: String,
    val os: String,
    val nameInt: String,
    val ttlInt: Int
) : DnsRecord(nameInt, ttlInt)

// APL Record (RFC 3123)
data class APLRecord(
    val addressFamily: Int, // e.g., 1 = IPv4, 2 = IPv6
    val prefix: String,
    val negation: Boolean,
    val nameInt: String,
    val ttlInt: Int
) : DnsRecord(nameInt, ttlInt)

// SSHFP Record (RFC 4255)
data class SSHFPRecord(
    val algorithm: Int,
    val fingerprintType: Int,
    val fingerprint: String,
    val nameInt: String,
    val ttlInt: Int
) : DnsRecord(nameInt, ttlInt)

// SVCB Record (RFC 9460)
data class SVCBRecord(
    val priority: Int,
    val targetName: String,
    val params: Map<String, String>,
    val nameInt: String,
    val ttlInt: Int
) : DnsRecord(nameInt, ttlInt)

// HTTPS Record (RFC 9460 — special case of SVCB)
data class HTTPSRecord(
    val priority: Int,
    val targetName: String,
    val params: Map<String, String>,
    val nameInt: String,
    val ttlInt: Int
) : DnsRecord(nameInt, ttlInt)

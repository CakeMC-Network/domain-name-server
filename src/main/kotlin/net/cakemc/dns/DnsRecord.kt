// DnsRecords.kt

package net.cakemc.dns

import net.cakemc.dns.types.DNSClass
import net.cakemc.dns.types.DNSRecordType

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


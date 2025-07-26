package net.cakemc.dns

import net.cakemc.dns.types.DNSFlags

data class DnsResponse(
    val transactionId: Int,
    val flags: List<DNSFlags>,
    val questions: Int,
    val answers: Int,
    val records: List<DnsRecord>
)
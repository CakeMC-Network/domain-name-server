package net.cakemc.dns

data class DnsResponse(
    val transactionId: Int,
    val flags: List<DNSFlags>,
    val questions: Int,
    val answers: Int,
    val records: List<DnsRecord>
)
package net.cakemc.dns

import net.cakemc.dns.register.DnsRegistry
import net.cakemc.dns.types.DNSRecordType
import net.cakemc.dns.units.DNSUtils

class DomainManager(
    val dnsRegistry: DnsRegistry
) {

    fun createResponse(query: ByteArray): ByteArray {
        val domain = extractHostName(query)
        val typeCode = ((query[query.lastIndex - 3].toInt() and 0xFF) shl 8) or (query[query.lastIndex - 2].toInt() and 0xFF)
        val type = DNSRecordType.fromCode(typeCode)

        val matched = dnsRegistry.findMatchingRecord(domain, type)
        return if (matched != null) {
            DNSUtils.buildResponse(query, matched)
        } else {
            DNSUtils.buildEmptyResponse(query)
        }
    }

    private fun extractHostName(query: ByteArray): String {
        var index = 12
        val parts = mutableListOf<String>()
        while (query[index] != 0.toByte()) {
            val len = query[index++].toInt()
            val label = query.copyOfRange(index, index + len).toString(Charsets.UTF_8)
            parts += label
            index += len
        }
        return parts.joinToString(".")
    }
}

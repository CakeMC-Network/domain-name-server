package net.cakemc.dns

object DNSMockServer {
    private val records = mutableListOf<DnsRecord>()

    fun addRecord(record: DnsRecord) {
        records += record
    }

    fun findMatchingRecord(name: String, type: DNSRecordType): DnsRecord? {
        return records.find { it.name == name && it.type == type }
    }

    fun createResponse(query: ByteArray): ByteArray {
        val domain = extractDomain(query)
        val typeCode = ((query[query.lastIndex - 3].toInt() and 0xFF) shl 8) or (query[query.lastIndex - 2].toInt() and 0xFF)
        val type = DNSRecordType.fromCode(typeCode)

        val matched = findMatchingRecord(domain, type)
        return if (matched != null) {
            DNSUtils.buildResponse(query, matched)
        } else {
            DNSUtils.buildEmptyResponse(query)
        }
    }

    private fun extractDomain(query: ByteArray): String {
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

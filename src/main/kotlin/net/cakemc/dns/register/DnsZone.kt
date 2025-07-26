package net.cakemc.dns.register

import net.cakemc.dns.DnsRecord
import net.cakemc.dns.types.DNSClass
import net.cakemc.dns.types.DNSRecordType
import java.util.concurrent.ConcurrentHashMap

/**
 * Represents a collection of DNS records grouped under a zone.
 */
class DnsZone(val id: ZoneId) {
    private val records: MutableMap<String, MutableMap<DNSRecordType, MutableList<DnsRecord>>> = ConcurrentHashMap()

    fun addRecord(record: DnsRecord) {
        records.computeIfAbsent(record.name.lowercase()) { ConcurrentHashMap() }
            .computeIfAbsent(record.type) { mutableListOf() }
            .add(record)
    }

    fun getRecords(
        name: String,
        type: DNSRecordType? = null,
        dnsClass: DNSClass? = null
    ): List<DnsRecord> {
        val nameKey = name.lowercase()
        val typeMap = records[nameKey] ?: return emptyList()

        return if (type != null) {
            typeMap[type].orEmpty().filter { dnsClass == null || it.recordClass == dnsClass }
        } else {
            typeMap.values.flatten().filter { dnsClass == null || it.recordClass == dnsClass }
        }
    }

    fun removeRecord(name: String, type: DNSRecordType? = null) {
        val nameKey = name.lowercase()
        val typeMap = records[nameKey] ?: return
        if (type != null) {
            typeMap.remove(type)
        } else {
            records.remove(nameKey)
        }
    }

    fun allRecords(): List<DnsRecord> {
        return records.values.flatMap { it.values.flatten() }
    }
}
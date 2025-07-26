package net.cakemc.dns.register

import net.cakemc.dns.DnsRecord
import net.cakemc.dns.types.DNSClass
import net.cakemc.dns.types.DNSRecordType
import java.util.concurrent.ConcurrentHashMap

/**
 * Singleton DNS registry to manage zones and records.
 */
class DnsRegistry {
    private val zones: MutableMap<ZoneId, DnsZone> = ConcurrentHashMap()

    fun registerZone(zoneId: ZoneId): DnsZone {
        return zones.computeIfAbsent(zoneId) { DnsZone(it) }
    }

    fun getZone(zoneId: ZoneId): DnsZone? = zones[zoneId]

    fun addRecordToZone(zoneId: ZoneId, record: DnsRecord) {
        val zone = registerZone(zoneId)
        zone.addRecord(record)
    }

    /**
     * Finds the first matching DNS record by name and type, regardless of zone.
     */
    fun findMatchingRecord(name: String, type: DNSRecordType): DnsRecord? {
        val normalized = name.lowercase()
        return zones.values.asSequence()
            .flatMap { it.getRecords(normalized, type).asSequence() }
            .firstOrNull()
    }

    fun getRecords(
        zoneId: ZoneId,
        name: String,
        type: DNSRecordType? = null,
        dnsClass: DNSClass? = null
    ): List<DnsRecord> {
        return zones[zoneId]?.getRecords(name, type, dnsClass).orEmpty()
    }

    fun removeRecord(zoneId: ZoneId, name: String, type: DNSRecordType? = null) {
        zones[zoneId]?.removeRecord(name, type)
    }

    fun listZones(): Set<ZoneId> = zones.keys

    fun clearZone(zoneId: ZoneId) {
        zones.remove(zoneId)
    }

    fun clearAll() {
        zones.clear()
    }
}
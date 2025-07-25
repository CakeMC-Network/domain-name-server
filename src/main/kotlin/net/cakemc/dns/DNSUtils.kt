package net.cakemc.dns

import java.io.ByteArrayOutputStream
import java.net.InetAddress
import java.nio.ByteBuffer
import java.util.*

object DNSUtils {

    fun createDNSQuery(domain: String): ByteArray {
        val out = ByteArrayOutputStream()

        // Transaction ID
        out.write(0x12)
        out.write(0x34)

        // Flags: QR=0, RD=1
        val flags = DNSFlags.RD.mask
        out.write((flags shr 8) and 0xFF)
        out.write(flags and 0xFF)

        // QDCOUNT=1, ANCOUNT=NSCOUNT=ARCOUNT=0
        out.write(byteArrayOf(0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00))

        // QNAME
        for (label in domain.split(".")) {
            out.write(label.length)
            out.write(label.toByteArray())
        }
        out.write(0x00)

        // QTYPE=A, QCLASS=IN
        out.write((DNSRecordType.A.code shr 8) and 0xFF)
        out.write(DNSRecordType.A.code and 0xFF)
        out.write((DNSClass.IN.code shr 8) and 0xFF)
        out.write(DNSClass.IN.code and 0xFF)

        return out.toByteArray()
    }

    fun parseDNSQuery(data: ByteArray) {
        val transactionId = ((data[0].toInt() and 0xFF) shl 8) or (data[1].toInt() and 0xFF)
        println("Transaction ID: 0x${transactionId.toString(16)}")

        var index = 12
        val domain = buildString {
            while (data[index] != 0.toByte()) {
                val len = data[index++].toInt()
                append(String(data, index, len))
                index += len
                append('.')
            }
        }.removeSuffix(".")

        index++ // null terminator
        val qtypeCode = ((data[index].toInt() and 0xFF) shl 8) or (data[index + 1].toInt() and 0xFF)
        val qclassCode = ((data[index + 2].toInt() and 0xFF) shl 8) or (data[index + 3].toInt() and 0xFF)

        val qtype = DNSRecordType.fromCode(qtypeCode)
        val qclass = DNSClass.fromCode(qclassCode)

        println("Query for domain: $domain")
        println("Type: $qtype ($qtypeCode), Class: $qclass ($qclassCode)")
    }

    fun buildResponse(query: ByteArray, record: DnsRecord): ByteArray {
        val out = ByteArrayOutputStream()

        out.write(query[0].toInt())
        out.write(query[1].toInt())

        val flags = DNSFlags.QR.mask or DNSFlags.RD.mask or DNSFlags.RA.mask
        out.write((flags shr 8) and 0xFF)
        out.write(flags and 0xFF)

        out.write(0x00); out.write(0x01) // QDCOUNT
        out.write(0x00); out.write(0x01) // ANCOUNT
        out.write(0x00); out.write(0x00) // NSCOUNT
        out.write(0x00); out.write(0x00) // ARCOUNT

        out.write(query.copyOfRange(12, query.size))

        val body = record.encode()

        out.write(0xC0); out.write(0x0C) // pointer to domain todo maybe change
        out.write((record.type.code shr 8) and 0xFF)
        out.write(record.type.code and 0xFF)
        out.write((record.recordClass.code shr 8) and 0xFF)
        out.write(record.recordClass.code and 0xFF)
        out.write((record.ttl shr 24) and 0xFF)
        out.write((record.ttl shr 16) and 0xFF)
        out.write((record.ttl shr 8) and 0xFF)
        out.write(record.ttl and 0xFF)
        out.write((body.size shr 8) and 0xFF)
        out.write(body.size and 0xFF)
        out.write(body)

        return out.toByteArray()
    }

    fun buildEmptyResponse(query: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(query[0].toInt())
        out.write(query[1].toInt())
        val flags = DNSFlags.QR.mask or DNSFlags.RD.mask or DNSFlags.RA.mask or 0x0003 // NXDOMAIN
        out.write((flags shr 8) and 0xFF)
        out.write(flags and 0xFF)

        out.write(0x00); out.write(0x01) // QDCOUNT
        out.write(0x00); out.write(0x00) // ANCOUNT
        out.write(0x00); out.write(0x00) // NSCOUNT
        out.write(0x00); out.write(0x00) // ARCOUNT

        out.write(query.copyOfRange(12, query.size))
        return out.toByteArray()
    }

    fun parseDNSResponse(data: ByteArray): DnsResponse {
        val transactionId = ((data[0].toInt() and 0xFF) shl 8) or (data[1].toInt() and 0xFF)
        val flagsRaw = ((data[2].toInt() and 0xFF) shl 8) or (data[3].toInt() and 0xFF)
        val qdCount = ((data[4].toInt() and 0xFF) shl 8) or (data[5].toInt() and 0xFF)
        val anCount = ((data[6].toInt() and 0xFF) shl 8) or (data[7].toInt() and 0xFF)

        var index = 12

        // Skip questions
        repeat(qdCount) {
            while (data[index] != 0.toByte()) {
                index += (data[index].toInt() and 0xFF) + 1
            }
            index++ // null terminator
            index += 4 // QTYPE + QCLASS
        }

        val records = mutableListOf<DnsRecord>()

        repeat(anCount) {
            val (name, nameEnd) = readName(data, index)
            index = nameEnd

            val typeCode = ((data[index++].toInt() and 0xFF) shl 8) or (data[index++].toInt() and 0xFF)
            val type = DNSRecordType.fromCode(typeCode)

            index += 2 // class
            val ttl = ((data[index++].toInt() and 0xFF) shl 24) or
                    ((data[index++].toInt() and 0xFF) shl 16) or
                    ((data[index++].toInt() and 0xFF) shl 8) or
                    (data[index++].toInt() and 0xFF)

            val rdLength = ((data[index++].toInt() and 0xFF) shl 8) or (data[index++].toInt() and 0xFF)
            val rdata = data.copyOfRange(index, index + rdLength)

            val record = try {
                type.construct().decode(rdata)
            } catch (e: Exception) {
                UnknownRecord(typeCode, rdata.joinToString(" ") { it.toUByte().toString() }, name, ttl)
            }

            records.add(record)
            index += rdLength
        }

        return DnsResponse(
            transactionId = transactionId,
            flags = DNSFlags.fromMask(flagsRaw),
            questions = qdCount,
            answers = anCount,
            records = records
        )
    }


    fun readName(data: ByteArray, startIndex: Int): Pair<String, Int> {
        var index = startIndex
        val labels = mutableListOf<String>()
        val jumped = false
        var endIndex = -1

        while (true) {
            val length = data[index].toInt() and 0xFF
            if (length == 0) {
                if (!jumped) endIndex = index + 1
                break
            }
            if ((length and 0xC0) == 0xC0) {
                val pointer = ((length and 0x3F) shl 8) or (data[index + 1].toInt() and 0xFF)
                val (jumpedName, _) = readName(data, pointer)
                labels.add(jumpedName)
                if (!jumped) endIndex = index + 2
                break
            } else {
                index++
                val label = data.copyOfRange(index, index + length).toString(Charsets.UTF_8)
                labels.add(label)
                index += length
            }
        }

        return labels.joinToString(".") to endIndex
    }


    fun encodeDomainName(domain: String): ByteArray {
        return domain.split(".").flatMap { label ->
            val bytes = label.toByteArray()
            listOf(bytes.size.toByte()) + bytes.toList()
        }.plus(0.toByte()).toByteArray()
    }

    fun decodeDomainName(data: ByteArray, offset: Int): Pair<String, Int> {
        var pos = offset
        val parts = mutableListOf<String>()
        while (data[pos] != 0.toByte()) {
            val len = data[pos].toInt()
            pos++
            val label = data.copyOfRange(pos, pos + len).toString(Charsets.UTF_8)
            parts.add(label)
            pos += len
        }
        return parts.joinToString(".") to (pos + 1)
    }

    fun hexStringToByteArray(hex: String): ByteArray {
        val cleaned = hex.replace(Regex("[^0-9A-Fa-f]"), "")
        return ByteArray(cleaned.length / 2) {
            cleaned.substring(it * 2, it * 2 + 2).toInt(16).toByte()
        }
    }

    fun byteArrayToHex(bytes: ByteArray): String =
        bytes.joinToString("") { "%02x".format(it) }

    fun encodeLOCSize(meters: Double): Byte {
        val cm = (meters * 100).toLong()
        var exponent = 0
        var base = cm
        while (base >= 10) {
            base /= 10
            exponent++
        }
        return ((base shl 4) or exponent.toLong()).toByte()
    }

    fun decodeLOCSize(b: Byte): Double {
        val base = ((b.toInt() ushr 4) and 0xF).toDouble()
        val exponent = (b.toInt() and 0xF).toDouble()
        return base * Math.pow(10.0, exponent) / 100.0
    }

    fun encodeLOCPosition(pos: String, isLat: Boolean): Int {
        val parts = pos.split(" ").map { it.trim() }
        val deg = parts[0].toInt()
        val min = parts[1].toInt()
        val sec = parts[2].toDouble()
        val hemisphere = parts[3].uppercase()

        var value = ((deg * 3600 + min * 60 + sec) * 1000).toLong()
        if ((isLat && hemisphere == "S") || (!isLat && hemisphere == "W")) {
            value = -value
        }
        return (value + 2_147_483_648).toInt()
    }

    fun decodeLOCPosition(encoded: Int, isLat: Boolean): String {
        var value = encoded - 2_147_483_648
        val hemisphere = if (isLat) if (value < 0) "S" else "N" else if (value < 0) "W" else "E"
        value = kotlin.math.abs(value)
        val totalSec = value / 1000.0
        val deg = (totalSec / 3600).toInt()
        val min = ((totalSec % 3600) / 60).toInt()
        val sec = totalSec % 60
        return "%d %d %.3f %s".format(deg, min, sec, hemisphere)
    }

    fun mapSvcParamKeyToCode(key: String): Int = when (key.lowercase()) {
        "alpn" -> 1
        "no-default-alpn" -> 2
        "port" -> 3
        "ipv4hint" -> 4
        "echconfig" -> 5
        "ipv6hint" -> 6
        else -> key.toIntOrNull() ?: 65000
    }

    fun mapSvcParamCodeToKey(code: Int): String = when (code) {
        1 -> "alpn"
        2 -> "no-default-alpn"
        3 -> "port"
        4 -> "ipv4hint"
        5 -> "echconfig"
        6 -> "ipv6hint"
        else -> "key$code"
    }

    fun encodeSvcParamValue(key: String, value: String): ByteArray {
        return when (key.lowercase()) {
            "alpn" -> {
                value.split(",").flatMap {
                    val b = it.toByteArray()
                    listOf(b.size.toByte()) + b.toList()
                }.toByteArray()
            }
            "port" -> ByteBuffer.allocate(2).putShort(value.toInt().toShort()).array()
            "ipv4hint", "ipv6hint" -> value.split(",").flatMap {
                InetAddress.getByName(it).address.toList()
            }.toByteArray()
            "echconfig" -> Base64.getDecoder().decode(value)
            "no-default-alpn" -> byteArrayOf()
            else -> value.toByteArray()
        }
    }

    fun decodeSvcParamValue(keyCode: Int, value: ByteArray): String {
        return when (keyCode) {
            1 -> {
                var pos = 0
                val result = mutableListOf<String>()
                while (pos < value.size) {
                    val len = value[pos++].toInt()
                    val str = value.copyOfRange(pos, pos + len).toString(Charsets.UTF_8)
                    result.add(str)
                    pos += len
                }
                result.joinToString(",")
            }
            2 -> ""
            3 -> ByteBuffer.wrap(value).short.toInt().toString()
            4, 6 -> value.toList().chunked(if (keyCode == 4) 4 else 16).joinToString(",") {
                InetAddress.getByAddress(it.toByteArray()).hostAddress
            }
            5 -> Base64.getEncoder().encodeToString(value)
            else -> value.toString(Charsets.UTF_8)
        }
    }


}

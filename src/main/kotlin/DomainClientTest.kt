import net.cakemc.dns.types.DNSRecordType
import net.cakemc.dns.network.UDPClient

fun main() {

    var start = System.currentTimeMillis()
    val client = UDPClient()
    println("client creation took ${System.currentTimeMillis() - start}ms")

    start = System.currentTimeMillis()
    val aRecord = client.query("example.com", DNSRecordType.A)
    println("client A query took ${System.currentTimeMillis() - start}ms")
    println(aRecord)

    start = System.currentTimeMillis()
    val aRecord2 = client.query("example.com", DNSRecordType.A)
    println("client A query took ${System.currentTimeMillis() - start}ms")
    println(aRecord2)

    start = System.currentTimeMillis()
    val aaaaRecord = client.query("example.com", DNSRecordType.AAAA)
    println("client AAAAA query took ${System.currentTimeMillis() - start}ms")
    println(aaaaRecord)

    start = System.currentTimeMillis()
    val aaaa2Record = client.query("example.com", DNSRecordType.AAAA)
    println("client AAAAA2 query took ${System.currentTimeMillis() - start}ms")
    println(aaaa2Record)

}
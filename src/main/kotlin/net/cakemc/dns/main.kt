package net.cakemc.dns

fun main() {
    // Add mock records
    DNSMockServer.addRecord(
        ARecord(
            nameInt = "example.com",
            address = "93.184.216.34",
            ttlInt = 30
        )
    )

    DNSMockServer.addRecord(
        TXTRecord(
            nameInt = "example.com",
            ttlInt = 20,
            texts = listOf("hello world!")
        )
    )

    println("=== DNS A Query ===")
    val aQuery = DNSUtils.createDNSQuery("example.com")
    DNSUtils.parseDNSQuery(aQuery)
    val aResponse = DNSMockServer.createResponse(aQuery)
    val response = DNSUtils.parseDNSResponse(aResponse)
    println(response)

    println("\n=== DNS TXT Query ===")
    val txtQuery = DNSUtils.createDNSQuery("example.com").apply {
        this[this.size - 4] = 0x00
        this[this.size - 3] = DNSRecordType.TXT.code.toByte()
    }
    DNSUtils.parseDNSQuery(txtQuery)
    val txtResponse = DNSMockServer.createResponse(txtQuery)
    val responseTxt = DNSUtils.parseDNSResponse(txtResponse)
    println(responseTxt)
}

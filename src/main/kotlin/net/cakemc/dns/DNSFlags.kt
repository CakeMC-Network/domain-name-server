package net.cakemc.dns

enum class DNSFlags(val mask: Int) {
    QR(0x8000),      // Query/Response
    OPCODE(0x7800),  // Operation Code
    AA(0x0400),      // Authoritative Answer
    TC(0x0200),      // Truncated
    RD(0x0100),      // Recursion Desired
    RA(0x0080),      // Recursion Available
    Z(0x0040),       // Reserved
    AD(0x0020),      // Authenticated Data
    CD(0x0010),      // Checking Disabled
    RCODE(0x000F);   // Response Code

    companion object {
        fun fromMask(mask: Int): List<DNSFlags> {
            return values().filter { flag -> (mask and flag.mask) != 0 }
        }
    }
}

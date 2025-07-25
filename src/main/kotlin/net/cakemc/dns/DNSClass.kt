package net.cakemc.dns;

enum class DNSClass(val code: Int) {
    IN(1),   // Internet
    CH(3),   // Chaos
    HS(4),   // Hesiod
    ANY(255);

    companion object {
        fun fromCode(code: Int): DNSClass? {
            return values().find { it.code == code }
        }
    }
}

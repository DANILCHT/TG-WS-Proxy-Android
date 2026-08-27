package com.flowseal.tgwsproxy.core

/** Port of proxy/balancer.py. */
object Balancer {

    private var domains: List<String> = emptyList()
    private val dcToDomain = HashMap<Int, String>()
    private val dcIds = intArrayOf(1, 2, 3, 4, 5, 203)

    @Synchronized
    fun updateDomainsList(list: List<String>) {
        if (domains.size == list.size && domains.toSet() == list.toSet()) return
        domains = list.toList()
        dcToDomain.clear()
        if (domains.isEmpty()) return
        for (dc in dcIds) {
            dcToDomain[dc] = domains[Crypto.randomInt(domains.size)]
        }
    }

    @Synchronized
    fun updateDomainForDc(dcId: Int, domain: String): Boolean {
        if (dcToDomain[dcId] == domain) return false
        dcToDomain[dcId] = domain
        return true
    }

    /** Active domain first, then the rest shuffled. */
    @Synchronized
    fun getDomainsForDc(dcId: Int): List<String> {
        val current = dcToDomain[dcId]
        val out = ArrayList<String>(domains.size + 1)
        if (current != null) out.add(current)
        val shuffled = domains.toMutableList()
        shuffled.shuffle()
        for (d in shuffled) if (d != current) out.add(d)
        return out
    }
}

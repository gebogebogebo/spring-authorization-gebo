package com.example.demo.service

import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.security.provisioning.JdbcUserDetailsManager
import org.springframework.stereotype.Service
import javax.sql.DataSource

@Service
class JdbcUserService(
    dataSource: DataSource,
    private val jdbcTemplate: JdbcTemplate
) : JdbcUserDetailsManager(dataSource) {
    data class AccountSummary(
        val username: String,
        val enabled: Boolean,
        val roles: Set<String>
    )

    fun findAllAccounts(): List<AccountSummary> {
        val sql = """
            SELECT u.username, u.enabled, a.authority
            FROM users u
            LEFT JOIN authorities a ON u.username = a.username
            ORDER BY u.username
        """.trimIndent()

        val rows = jdbcTemplate.query(sql) { rs, _ ->
            Triple(
                rs.getString("username"),
                rs.getBoolean("enabled"),
                rs.getString("authority")
            )
        }

        val grouped = LinkedHashMap<String, Pair<Boolean, MutableSet<String>>>()
        for ((username, enabled, authority) in rows) {
            val entry = grouped.getOrPut(username) { enabled to linkedSetOf() }
            if (!authority.isNullOrBlank()) {
                entry.second.add(authority)
            }
        }

        return grouped.map { (username, data) ->
            AccountSummary(username, data.first, data.second.toSet())
        }
    }
}

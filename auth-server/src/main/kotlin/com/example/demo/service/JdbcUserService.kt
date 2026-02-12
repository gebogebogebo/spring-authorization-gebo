package com.example.demo.service

import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.security.core.userdetails.User
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.provisioning.JdbcUserDetailsManager
import org.springframework.stereotype.Service
import javax.sql.DataSource

@Service
class JdbcUserService(
    dataSource: DataSource,
    private val jdbcTemplate: JdbcTemplate,
    private val passwordEncoder: PasswordEncoder
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

    fun findAccountByUsername(username: String): AccountSummary? {
        return findAllAccounts().find { it.username == username }
    }

    fun createAccount(username: String, password: String, enabled: Boolean = true, roles: Set<String> = setOf("USER")) {
        val encodedPassword = passwordEncoder.encode(password)
        val authorities = roles.map { if (it.startsWith("ROLE_")) it else "ROLE_$it" }.toSet()
        val user = User.builder()
            .username(username)
            .password(encodedPassword)
            .roles(*authorities.map { it.removePrefix("ROLE_") }.toTypedArray())
            .disabled(!enabled)
            .build()
        createUser(user)
    }
}

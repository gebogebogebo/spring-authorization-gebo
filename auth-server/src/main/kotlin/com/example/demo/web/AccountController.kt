package com.example.demo.web

import com.example.demo.service.JdbcUserService
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.DeleteMapping
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RestController

data class CreateAccountRequest(
    val username: String,
    val password: String,
    val enabled: Boolean = true,
    val roles: Set<String> = setOf("USER")
)

@RestController
class AccountController(
    private val jdbcUserService: JdbcUserService
) {
    @GetMapping("/api/accounts")
    fun listAccounts(): List<JdbcUserService.AccountSummary> {
        return jdbcUserService.findAllAccounts()
    }

    @PostMapping("/api/accounts")
    fun createAccount(@RequestBody request: CreateAccountRequest): ResponseEntity<JdbcUserService.AccountSummary> {
        if (jdbcUserService.userExists(request.username)) {
            return ResponseEntity.status(HttpStatus.CONFLICT).build()
        }
        jdbcUserService.createAccount(
            username = request.username,
            password = request.password,
            enabled = request.enabled,
            roles = request.roles
        )
        val summary = jdbcUserService.findAccountByUsername(request.username)
            ?: return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build()
        return ResponseEntity.status(HttpStatus.CREATED).body(summary)
    }

    @DeleteMapping("/api/accounts/{username}")
    fun deleteAccount(@PathVariable username: String): ResponseEntity<Unit> {
        if (!jdbcUserService.userExists(username)) {
            return ResponseEntity.notFound().build()
        }
        jdbcUserService.deleteUser(username)
        return ResponseEntity.noContent().build()
    }
}

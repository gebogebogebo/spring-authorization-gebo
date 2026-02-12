package com.example.demo.web

import com.example.demo.service.JdbcUserService
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController

@RestController
class AccountController(
    private val jdbcUserService: JdbcUserService
) {
    @GetMapping("/api/accounts")
    fun listAccounts(): List<JdbcUserService.AccountSummary> {
        return jdbcUserService.findAllAccounts()
    }
}

package com.example.demo.web

data class CreateAccountRequest(
    val username: String,
    val password: String,
    val enabled: Boolean = true,
    val roles: Set<String> = setOf("USER")
)

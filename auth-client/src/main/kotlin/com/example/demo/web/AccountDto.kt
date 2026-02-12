package com.example.demo.web

/**
 * auth-server /api/accounts のレスポンス用 DTO。
 * トップレベルに定義して RestClient のデシリアライズを確実にする。
 */
data class AccountDto(
    val username: String,
    val enabled: Boolean,
    val roles: List<String>
)

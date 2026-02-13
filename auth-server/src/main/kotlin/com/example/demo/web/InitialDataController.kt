package com.example.demo.web

import com.example.demo.service.JdbcUserService
import org.springframework.http.ResponseEntity
import org.springframework.security.core.userdetails.User
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.core.oidc.OidcScopes
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RestController
import java.util.UUID

@RestController
class InitialDataController(
    private val registeredClientRepository: RegisteredClientRepository,
    private val jdbcUserService: JdbcUserService,
    private val passwordEncoder: PasswordEncoder,
) {
    @PostMapping("/api/initialize")
    fun initialize(): ResponseEntity<Map<String, String>> {

        // クライアントが既に存在する場合はスキップ
        val clientId = "gebo-client"
        if (registeredClientRepository.findByClientId(clientId) == null) {
            // TODO Spring Security 7.0.2 では デフォルトで PKCE が有効になったので、ここでは無効にする
            // 参考
            // org.springframework.security.oauth2.server.authorization.settings.ClientSettings.builder
            // 	public static Builder builder() {
            //		return new Builder().requireProofKey(true).requireAuthorizationConsent(false);
            //	}

            val messagingClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(clientId)
                .clientSecret(passwordEncoder.encode("secret"))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .redirectUri("http://localhost:8080/login/oauth2/code/gebo-client-oidc")
                .redirectUri("http://localhost:8080/authorized")
                .postLogoutRedirectUri("http://localhost:8080/")
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                .scope("message.read")
                .scope("message.write")
                .scope("user.read")
                .clientSettings(
                    ClientSettings.builder()
                        .requireAuthorizationConsent(true)
                        .requireProofKey(false)         // TODO: これを追加
                        .build())
                .build()

            registeredClientRepository.save(messagingClient)
        }

        // ユーザー作成（既存ユーザーはパスワードを BCrypt に更新してログイン可能にする）
        val encodedPassword = passwordEncoder.encode("password")
        val user1 = "user1"
        if (!jdbcUserService.userExists(user1)) {
            val user = User.builder()
                .username(user1)
                .password(encodedPassword)
                .roles("USER")
                .build()
            jdbcUserService.createUser(user)
        } else {
            val existing = jdbcUserService.loadUserByUsername(user1)
            val updated = User.builder()
                .username(existing.username)
                .password(encodedPassword)
                .authorities(existing.authorities)
                .accountExpired(!existing.isAccountNonExpired)
                .accountLocked(!existing.isAccountNonLocked)
                .credentialsExpired(!existing.isCredentialsNonExpired)
                .disabled(!existing.isEnabled)
                .build()
            jdbcUserService.updateUser(updated)
        }

        val admin = "admin"
        if (!jdbcUserService.userExists(admin)) {
            val user = User.builder()
                .username(admin)
                .password(encodedPassword)
                .roles("ADMIN")
                .build()
            jdbcUserService.createUser(user)
        } else {
            val existing = jdbcUserService.loadUserByUsername(admin)
            val updated = User.builder()
                .username(existing.username)
                .password(encodedPassword)
                .authorities(existing.authorities)
                .accountExpired(!existing.isAccountNonExpired)
                .accountLocked(!existing.isAccountNonLocked)
                .credentialsExpired(!existing.isCredentialsNonExpired)
                .disabled(!existing.isEnabled)
                .build()
            jdbcUserService.updateUser(updated)
        }

        return ResponseEntity.ok(
            mapOf(
                "message" to "初期化が完了しました",
            )
        )
    }
}

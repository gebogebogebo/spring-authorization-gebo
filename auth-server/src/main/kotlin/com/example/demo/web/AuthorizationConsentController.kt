package com.example.demo.web

import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames
import org.springframework.security.oauth2.core.oidc.OidcScopes
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.stereotype.Controller
import org.springframework.ui.Model
import org.springframework.util.StringUtils
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestParam
import java.security.Principal

@Controller
class AuthorizationConsentController(
    private val registeredClientRepository: RegisteredClientRepository,
    private val authorizationConsentService: OAuth2AuthorizationConsentService
) {
    @GetMapping(value = ["/oauth2/consent"])
    fun consent(
        principal: Principal,
        authentication: Authentication,
        model: Model,
        @RequestParam(OAuth2ParameterNames.CLIENT_ID) clientId: String,
        @RequestParam(OAuth2ParameterNames.SCOPE) scope: String,
        @RequestParam(OAuth2ParameterNames.STATE) state: String,
        @RequestParam(name = OAuth2ParameterNames.USER_CODE, required = false) userCode: String?
    ): String {
        val registeredClient = registeredClientRepository.findByClientId(clientId)
            ?: throw IllegalArgumentException("Invalid client_id: $clientId")

        val currentAuthorizationConsent = authorizationConsentService.findById(
            registeredClient.id,
            principal.name
        )

        val authorizedScopes = currentAuthorizationConsent?.scopes ?: emptySet()

        val requestedScopes = StringUtils.delimitedListToStringArray(scope, " ")
            .filterNot { it == OidcScopes.OPENID }

        // ユーザーのロールを取得
        val isAdmin = authentication.authorities.any { it.authority == "ROLE_ADMIN" }

        // ロールに応じて実際に許可するスコープを決定（Downscoping）
        // この処理はカスタマイザーでも行われるが、画面表示のために必要
        val allowedScopes = if (isAdmin) {
            requestedScopes.toSet()
        } else {
            requestedScopes.filter { it == OidcScopes.PROFILE }.toSet()
        }

        // 許可するスコープのうち、まだ承認されていないもの
        val scopesToApprove = allowedScopes.filterNot { it in authorizedScopes }.toSet()

        // すでに承認済みのスコープ（許可対象のもののみ）
        val previouslyApprovedScopes = allowedScopes.filter { it in authorizedScopes }.toSet()

        model.apply {
            addAttribute("clientId", clientId)
            addAttribute("state", state)
            addAttribute("scopes", withDescription(scopesToApprove))
            addAttribute("scopesToApprove", scopesToApprove)
            addAttribute("previouslyApprovedScopes", withDescription(previouslyApprovedScopes))
            addAttribute("principalName", principal.name)
            addAttribute("userCode", userCode)
            addAttribute("requestURI", if (StringUtils.hasText(userCode)) "/oauth2/device_verification" else "/oauth2/authorize")
            addAttribute("isAdmin", isAdmin)
        }

        return "consent"
    }

    data class ScopeWithDescription(val scope: String) {
        val description: String = scopeDescriptions[scope] ?: DEFAULT_DESCRIPTION

        companion object {
            private const val DEFAULT_DESCRIPTION =
                "UNKNOWN SCOPE - We cannot provide information about this permission, use caution when granting this."

            private val scopeDescriptions = mapOf(
                OidcScopes.PROFILE to "このアプリケーションは、あなたのプロフィール情報を読み取ることができます。",
                "users.read" to "このアプリケーションは、ユーザー情報を読み取ることができます。",
                "users.write" to "このアプリケーションは、ユーザーを作成・編集することができます。",
                "users.delete" to "このアプリケーションは、ユーザーを削除することができます。",
                "other.scope" to "This is another scope example of a scope description."
            )
        }
    }

    companion object {
        private fun withDescription(scopes: Set<String>) = scopes.map { ScopeWithDescription(it) }.toSet()
    }
}

package com.example.demo.config

import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.core.oidc.OidcScopes
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationProvider
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationConsentAuthenticationProvider
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationConsentAuthenticationToken
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository

/**
 * ダウンスコーピング（Downscoping）を実装するカスタム AuthenticationProvider
 *
 * ユーザーのロールに応じて、実際に許可するスコープを制限します：
 * - ROLE_ADMIN: クライアントがリクエストした全スコープを許可
 * - ROLE_USER: profile のみを許可
 */
class DownscopingAuthorizationConsentAuthenticationProvider(
    private val registeredClientRepository: RegisteredClientRepository,
    private val authorizationService: OAuth2AuthorizationService,
    private val authorizationConsentService: OAuth2AuthorizationConsentService
) : AuthenticationProvider {

    private val codeRequestDelegate = OAuth2AuthorizationCodeRequestAuthenticationProvider(
        registeredClientRepository,
        authorizationService,
        authorizationConsentService
    )

    private val consentDelegate = OAuth2AuthorizationConsentAuthenticationProvider(
        registeredClientRepository,
        authorizationService,
        authorizationConsentService
    )

    override fun authenticate(authentication: Authentication): Authentication? {
        // OAuth2AuthorizationCodeRequestAuthenticationTokenの場合、ダウンスコーピングをチェック
        if (authentication is OAuth2AuthorizationCodeRequestAuthenticationToken) {
            return handleAuthorizationCodeRequest(authentication)
        }

        // OAuth2AuthorizationConsentAuthenticationTokenの場合、consentDelegateに委譲
        if (authentication is OAuth2AuthorizationConsentAuthenticationToken) {
            return consentDelegate.authenticate(authentication)
        }

        return null
    }

    override fun supports(authentication: Class<*>): Boolean {
        return OAuth2AuthorizationCodeRequestAuthenticationToken::class.java.isAssignableFrom(authentication) ||
                OAuth2AuthorizationConsentAuthenticationToken::class.java.isAssignableFrom(authentication)
    }

    private fun handleAuthorizationCodeRequest(authenticationToken: OAuth2AuthorizationCodeRequestAuthenticationToken): Authentication {
        val principal = authenticationToken.principal as Authentication
        val clientId = authenticationToken.clientId

        // RegisteredClient を取得して id (UUID) を取得
        val registeredClient = registeredClientRepository.findByClientId(clientId)
            ?: throw IllegalArgumentException("Invalid client_id: $clientId")

        // ユーザーのロールを取得
        val isAdmin = principal.authorities.any { it.authority == "ROLE_ADMIN" }

        // リクエストされたスコープを取得
        val requestedScopes = authenticationToken.scopes.filter { it != OidcScopes.OPENID }.toSet()

        // ロールに応じて実際に許可するスコープを決定（Downscoping）
        val allowedScopes = if (isAdmin) {
            requestedScopes
        } else {
            requestedScopes.filter { it == OidcScopes.PROFILE }.toSet()
        }

        // 既存の承認済みスコープを取得（registeredClient.id を使用）
        val existingConsent = authorizationConsentService.findById(registeredClient.id, principal.name)
        val authorizedScopes = existingConsent?.scopes ?: emptySet()

        // ダウンスコーピング後のスコープのうち、まだ承認されていないものを取得
        val scopesToApprove = allowedScopes.filterNot { it in authorizedScopes }.toSet()

        // すべて承認済みの場合、consentを保存してスコープをallowedScopesに変更したトークンを渡す
        if (scopesToApprove.isEmpty() && allowedScopes.isNotEmpty()) {
            // 既存のconsentがあればそれを使用、なければ新規作成
            val consentBuilder = if (existingConsent != null) {
                OAuth2AuthorizationConsent.from(existingConsent)
            } else {
                OAuth2AuthorizationConsent.withId(registeredClient.id, principal.name)
            }

            // 許可されたスコープを追加
            allowedScopes.forEach { scope ->
                consentBuilder.scope(scope)
            }

            // consentを保存
            authorizationConsentService.save(consentBuilder.build())

            // allowedScopes + openid で新しいトークンを作成
            // これによりフレームワークは全てのスコープが承認済みと判断し、consent画面をスキップする
            val scopesWithOpenId = allowedScopes.toMutableSet().apply {
                if (authenticationToken.scopes.contains(OidcScopes.OPENID)) {
                    add(OidcScopes.OPENID)
                }
            }

            val modifiedToken = OAuth2AuthorizationCodeRequestAuthenticationToken(
                authenticationToken.authorizationUri,
                clientId,
                principal,
                authenticationToken.redirectUri,
                authenticationToken.state,
                scopesWithOpenId,
                authenticationToken.additionalParameters
            )

            // 修正されたトークンでdelegate処理を実行
            return codeRequestDelegate.authenticate(modifiedToken) as Authentication
        }

        // 未承認のスコープがある場合は、元のトークンでdelegate処理を実行（consent画面が表示される）
        return codeRequestDelegate.authenticate(authenticationToken) as Authentication
    }
}

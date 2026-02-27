package com.example.demo.web

import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient
import org.springframework.security.oauth2.client.endpoint.OAuth2RefreshTokenGrantRequest
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository
import org.springframework.security.oauth2.core.oidc.OidcIdToken
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser
import org.springframework.security.oauth2.core.oidc.user.OidcUser
import org.springframework.stereotype.Controller
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.servlet.mvc.support.RedirectAttributes
import java.time.Instant

@Controller
class RefreshTokenController(
    private val clientRegistrationRepository: ClientRegistrationRepository,
    private val authorizedClientService: OAuth2AuthorizedClientService,
    private val refreshTokenResponseClient: OAuth2AccessTokenResponseClient<OAuth2RefreshTokenGrantRequest>
) {
    private val registrationId = "gebo-client-oidc"

    @PostMapping("/refresh-token")
    fun refreshToken(
        authentication: OAuth2AuthenticationToken?,
        redirectAttributes: RedirectAttributes
    ): String {
        if (authentication == null) {
            return redirectWithMessage(redirectAttributes, "未認証です。再度ログインしてください。", "/view-token")
        }

        val clientRegistration = clientRegistrationRepository.findByRegistrationId(registrationId)
            ?: return "redirect:/view-token"

        val authorizedClient: OAuth2AuthorizedClient? =
            authorizedClientService.loadAuthorizedClient(registrationId, authentication.name)
        val refreshToken = authorizedClient?.refreshToken

        if (authorizedClient == null || refreshToken == null) {
            return "redirect:/oauth2/authorization/$registrationId"
        }

        return try {
            val request = OAuth2RefreshTokenGrantRequest(
                clientRegistration,
                authorizedClient.accessToken,
                refreshToken
            )
            val tokenResponse = refreshTokenResponseClient.getTokenResponse(request)

            updateIdToken(authentication, tokenResponse.additionalParameters["id_token"] as? String)

            val newAuthorizedClient = OAuth2AuthorizedClient(
                clientRegistration,
                authentication.name,
                tokenResponse.accessToken,
                tokenResponse.refreshToken ?: refreshToken
            )
            authorizedClientService.saveAuthorizedClient(newAuthorizedClient, authentication)

            redirectWithMessage(redirectAttributes, "トークンを再取得しました。", "/view-token")
        } catch (e: Exception) {
            redirectWithMessage(
                redirectAttributes,
                "トークン再取得に失敗しました。再度ログインしてください。",
                "/oauth2/authorization/$registrationId"
            )
        }
    }

    private fun updateIdToken(authentication: OAuth2AuthenticationToken, newIdTokenValue: String?) {
        if (newIdTokenValue == null) return

        val oidcUser = authentication.principal as? OidcUser ?: return

        val now = Instant.now()
        val newIdToken = OidcIdToken(
            newIdTokenValue,
            now,
            now.plusSeconds(3600),
            oidcUser.idToken.claims
        )

        val newOidcUser = DefaultOidcUser(
            oidcUser.authorities,
            newIdToken,
            oidcUser.userInfo
        )

        val newAuthentication = OAuth2AuthenticationToken(
            newOidcUser,
            oidcUser.authorities,
            authentication.authorizedClientRegistrationId
        )

        SecurityContextHolder.getContext().authentication = newAuthentication
    }

    private fun redirectWithMessage(
        redirectAttributes: RedirectAttributes,
        message: String,
        path: String
    ): String {
        redirectAttributes.addFlashAttribute("refreshMessage", message)
        return "redirect:$path"
    }
}

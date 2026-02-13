package com.example.demo.web

import org.springframework.security.oauth2.client.OAuth2AuthorizedClient
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient
import org.springframework.security.oauth2.client.endpoint.OAuth2RefreshTokenGrantRequest
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository
import org.springframework.stereotype.Controller
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.servlet.mvc.support.RedirectAttributes

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
            redirectAttributes.addFlashAttribute("refreshMessage", "未認証です。再度ログインしてください。")
            return "redirect:/view-token"
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
            val newAccessToken = tokenResponse.accessToken
            val newRefreshToken = tokenResponse.refreshToken ?: refreshToken
            val newAuthorizedClient = OAuth2AuthorizedClient(
                clientRegistration,
                authentication.name,
                newAccessToken,
                newRefreshToken
            )
            authorizedClientService.saveAuthorizedClient(newAuthorizedClient, authentication)
            redirectAttributes.addFlashAttribute("refreshMessage", "トークンを再取得しました。")
            "redirect:/view-token"
        } catch (e: Exception) {
            redirectAttributes.addFlashAttribute("refreshMessage", "トークン再取得に失敗しました。再度ログインしてください。")
            "redirect:/oauth2/authorization/$registrationId"
        }
    }
}

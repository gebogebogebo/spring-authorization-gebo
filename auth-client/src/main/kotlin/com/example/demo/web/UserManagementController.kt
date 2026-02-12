package com.example.demo.web

import com.example.demo.service.OidcTokenService
import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.core.ParameterizedTypeReference
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken
import org.springframework.stereotype.Controller
import org.springframework.ui.Model
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.client.RestClient
import org.springframework.web.client.RestClientResponseException

@Controller
class UserManagementController(
    private val oidcTokenService: OidcTokenService,
    @Qualifier("default-client-rest-client")
    private val restClient: RestClient
) {
    data class Account(
        val username: String,
        val enabled: Boolean,
        val roles: List<String>
    )

    @GetMapping("/user-management")
    fun userManagement(
        model: Model,
        authentication: OAuth2AuthenticationToken?
    ): String {
        val accessToken = oidcTokenService.getAccessTokenValue(authentication)
        if (accessToken == null) {
            model.addAttribute("errorMessage", "Access token not found.")
            model.addAttribute("accounts", emptyList<Account>())
            return "user-management"
        }

        return try {
            val accounts = restClient
                .get()
                .uri("http://localhost:9000/api/accounts")
                .header("Authorization", "Bearer $accessToken")
                .retrieve()
                .body(object : ParameterizedTypeReference<List<Account>>() {}) ?: emptyList()

            model.addAttribute("accounts", accounts)
            "user-management"
        } catch (ex: RestClientResponseException) {
            val message = when (ex.statusCode.value()) {
                401 -> "Unauthorized. Please sign in."
                403 -> "Forbidden. Admin role required."
                else -> "Failed to load accounts."
            }
            model.addAttribute("errorMessage", message)
            model.addAttribute("accounts", emptyList<Account>())
            "user-management"
        }
    }
}

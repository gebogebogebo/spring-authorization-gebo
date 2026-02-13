package com.example.demo.web

import com.example.demo.service.OidcTokenService
import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.beans.factory.annotation.Value
import org.springframework.core.ParameterizedTypeReference
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken
import org.springframework.stereotype.Controller
import org.springframework.ui.Model
import org.springframework.web.bind.annotation.DeleteMapping
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.client.RestClient
import org.springframework.web.client.RestClientResponseException
import jakarta.servlet.http.HttpServletRequest

@Controller
class UserManagementController(
    private val oidcTokenService: OidcTokenService,
    @Qualifier("default-client-rest-client")
    private val restClient: RestClient,
    @Value("\${app.auth-server.url}")
    private val authServerUrl: String
) {
    data class CreateAccountRequest(
        val username: String,
        val password: String,
        val enabled: Boolean = true,
        val roles: Set<String> = setOf("USER")
    )

    @GetMapping("/user-management")
    fun userManagement(
        model: Model,
        authentication: OAuth2AuthenticationToken?,
        request: HttpServletRequest
    ): String {
        model.addAttribute("_csrf", request.getAttribute("org.springframework.security.web.csrf.CsrfToken"))
        val accessToken = oidcTokenService.getAccessTokenValue(authentication)
        if (accessToken == null) {
            model.addAttribute("errorMessage", "Access token not found.")
            model.addAttribute("accounts", emptyList<AccountDto>())
            return "user-management"
        }

        return try {
            val accounts: List<AccountDto> = restClient
                .get()
                .uri("$authServerUrl/api/accounts")
                .header("Authorization", "Bearer $accessToken")
                .retrieve()
                .body(object : ParameterizedTypeReference<List<AccountDto>>() {}) ?: emptyList()

            model.addAttribute("accounts", accounts)
            "user-management"
        } catch (ex: RestClientResponseException) {
            val message = when (ex.statusCode.value()) {
                401 -> "Unauthorized. Please sign in."
                403 -> "Forbidden. Admin role required."
                else -> "Failed to load accounts."
            }
            model.addAttribute("errorMessage", message)
            model.addAttribute("accounts", emptyList<AccountDto>())
            "user-management"
        }
    }

    @PostMapping("/user-management/accounts")
    fun createAccount(
        @RequestBody request: CreateAccountRequest,
        authentication: OAuth2AuthenticationToken?
    ): ResponseEntity<Any> {
        val accessToken = oidcTokenService.getAccessTokenValue(authentication) ?: return ResponseEntity.status(
            HttpStatus.UNAUTHORIZED
        ).body(mapOf("error" to "Access token not found."))
        return try {
            val created = restClient
                .post()
                .uri("$authServerUrl/api/accounts")
                .header("Authorization", "Bearer $accessToken")
                .body(request)
                .retrieve()
                .toEntity(object : ParameterizedTypeReference<AccountDto>() {})
            ResponseEntity.status(created.statusCode).body(created.body)
        } catch (ex: RestClientResponseException) {
            val body = mapOf("error" to (ex.responseBodyAsString.takeIf { it.isNotBlank() } ?: ex.message ?: "Failed to create account."))
            ResponseEntity.status(ex.statusCode).body(body)
        }
    }

    @DeleteMapping("/user-management/accounts/{username}")
    fun deleteAccount(
        @PathVariable username: String,
        authentication: OAuth2AuthenticationToken?
    ): ResponseEntity<Any> {
        val accessToken = oidcTokenService.getAccessTokenValue(authentication)
            ?: return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(mapOf("error" to "Access token not found."))
        return try {
            restClient
                .delete()
                .uri("$authServerUrl/api/accounts/$username")
                .header("Authorization", "Bearer $accessToken")
                .retrieve()
                .toBodilessEntity()
            ResponseEntity.noContent().build()
        } catch (ex: RestClientResponseException) {
            val body = mapOf("error" to (ex.responseBodyAsString.takeIf { it.isNotBlank() } ?: ex.message ?: "Failed to delete account."))
            ResponseEntity.status(ex.statusCode).body(body)
        }
    }
}

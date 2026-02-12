package com.example.demo.web

import com.nimbusds.jwt.SignedJWT
import jakarta.servlet.http.HttpSession
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken
import org.springframework.stereotype.Controller
import org.springframework.ui.Model
import org.springframework.web.bind.annotation.GetMapping
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter

@Controller
class HomeController(
    private val authorizedClientService: OAuth2AuthorizedClientService
) {
    private val jstZoneId = ZoneId.of("Asia/Tokyo")
    private val jstFormatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss XXX")

    @GetMapping("/home")
    fun home(
        model: Model,
        session: HttpSession,
        authentication: Authentication?
    ): String {
        val createdAt = Instant.ofEpochMilli(session.creationTime)
            .atZone(jstZoneId)
            .format(jstFormatter)
        val lastAccessedAt = Instant.ofEpochMilli(session.lastAccessedTime)
            .atZone(jstZoneId)
            .format(jstFormatter)
        val ttlSeconds = session.maxInactiveInterval
        val username = authentication?.name
        val authorities = authentication?.authorities
            ?.mapNotNull { it.authority }
            ?.sorted()
        val roles = authentication?.let { loadRolesFromAccessToken(it) }
        val scopes = authorities
            ?.filter { it.startsWith("SCOPE_") }
        model.addAttribute("sessionId", session.id)
        model.addAttribute("sessionCreatedAt", createdAt)
        model.addAttribute("sessionLastAccessedAt", lastAccessedAt)
        model.addAttribute("sessionTtlSeconds", ttlSeconds)
        model.addAttribute("username", username)
        model.addAttribute("roles", roles)
        model.addAttribute("scopes", scopes)
        return "home"
    }

    private fun loadRolesFromAccessToken(authentication: Authentication): List<String>? {
        val oauthToken = authentication as? OAuth2AuthenticationToken ?: return null
        val authorizedClient: OAuth2AuthorizedClient? = authorizedClientService.loadAuthorizedClient(
            oauthToken.authorizedClientRegistrationId,
            oauthToken.name
        )
        val tokenValue = authorizedClient?.accessToken?.tokenValue ?: return null
        return try {
            val claims = SignedJWT.parse(tokenValue).jwtClaimsSet
            claims.getStringListClaim("roles")?.sorted()
        } catch (ex: Exception) {
            null
        }
    }
}

package com.example.demo.config

import com.nimbusds.jwt.SignedJWT
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.authorization.AuthorizationDecision
import org.springframework.security.config.Customizer.withDefaults
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.access.intercept.RequestAuthorizationContext
import com.example.demo.service.HttpSessionOAuth2AuthorizedClientService
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler

@EnableWebSecurity
@Configuration(proxyBeanMethods = false)
class SecurityConfig {

	@Bean
	fun authorizedClientService(clientRegistrationRepository: ClientRegistrationRepository): OAuth2AuthorizedClientService =
		HttpSessionOAuth2AuthorizedClientService(clientRegistrationRepository)

	@Bean
	fun securityFilterChain(
		http: HttpSecurity,
		clientRegistrationRepository: ClientRegistrationRepository,
		authorizedClientService: OAuth2AuthorizedClientService
	): SecurityFilterChain {
		http
			.authorizeHttpRequests { authorize ->
				authorize
					.requestMatchers("/", "/index", "/webjars/**", "/assets/**", "/jwks", "/logged-out", "/api/initialize")
					.permitAll()
					.requestMatchers("/user-management/**").access { authentication, context ->
						hasJwtRole(authentication.get(), authorizedClientService, "ROLE_ADMIN")
					}
					.anyRequest().authenticated()
			}
			.csrf { csrf -> csrf.ignoringRequestMatchers("/api/initialize") }
			.oauth2Login { oauth2Login ->
				oauth2Login.loginPage("/oauth2/authorization/gebo-client-oidc")
			}
			.oauth2Client(withDefaults())
			.logout { logout ->
				logout.logoutSuccessHandler(oidcLogoutSuccessHandler(clientRegistrationRepository))
			}
		return http.build()
	}

	private fun hasJwtRole(
		authentication: org.springframework.security.core.Authentication,
		authorizedClientService: OAuth2AuthorizedClientService,
		role: String
	): AuthorizationDecision {
		val oauthToken = authentication as? OAuth2AuthenticationToken ?: return AuthorizationDecision(false)
		val authorizedClient: OAuth2AuthorizedClient? = authorizedClientService.loadAuthorizedClient(
			oauthToken.authorizedClientRegistrationId,
			oauthToken.name
		)
		val tokenValue = authorizedClient?.accessToken?.tokenValue ?: return AuthorizationDecision(false)

		return try {
			val claims = SignedJWT.parse(tokenValue).jwtClaimsSet
			val roles = claims.getStringListClaim("roles") ?: emptyList()
			AuthorizationDecision(roles.contains(role))
		} catch (ex: Exception) {
			AuthorizationDecision(false)
		}
	}

	private fun oidcLogoutSuccessHandler(
		clientRegistrationRepository: ClientRegistrationRepository
	): LogoutSuccessHandler {
		val oidcLogoutSuccessHandler =
			OidcClientInitiatedLogoutSuccessHandler(clientRegistrationRepository)

		// Set the location that the End-User's User Agent will be redirected to
		// after the logout has been performed at the Provider
		oidcLogoutSuccessHandler.setPostLogoutRedirectUri("{baseUrl}/")

		return oidcLogoutSuccessHandler
	}
}

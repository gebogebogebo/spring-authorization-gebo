package com.example.demo.config

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.Customizer.withDefaults
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler

@EnableWebSecurity
@Configuration(proxyBeanMethods = false)
class SecurityConfig {

	@Bean
	fun securityFilterChain(
		http: HttpSecurity,
		clientRegistrationRepository: ClientRegistrationRepository
	): SecurityFilterChain {
		http
			.authorizeHttpRequests { authorize ->
				authorize
					.requestMatchers("/", "/index", "/webjars/**", "/assets/**", "/jwks", "/logged-out", "/api/initialize")
					.permitAll()
					.anyRequest().authenticated()
			}
			.csrf { csrf -> csrf.ignoringRequestMatchers("/api/initialize") }
			.oauth2Login { oauth2Login ->
				oauth2Login.loginPage("/oauth2/authorization/messaging-client-oidc")
			}
			.oauth2Client(withDefaults())
			.logout { logout ->
				logout.logoutSuccessHandler(oidcLogoutSuccessHandler(clientRegistrationRepository))
			}
		return http.build()
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

package com.example.demo.config

import com.nimbusds.jwt.SignedJWT
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.Customizer.withDefaults
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser
import org.springframework.security.oauth2.core.oidc.user.OidcUser
import org.springframework.security.web.SecurityFilterChain
import com.example.demo.service.HttpSessionOAuth2AuthorizedClientService
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler

@EnableWebSecurity
@Configuration(proxyBeanMethods = false)
class SecurityConfig {

	@Bean
	fun authorizedClientService(clientRegistrationRepository: ClientRegistrationRepository): OAuth2AuthorizedClientService =
		HttpSessionOAuth2AuthorizedClientService(clientRegistrationRepository)

	@Bean
	fun oidcUserService(): OAuth2UserService<OidcUserRequest, OidcUser> {
		val delegate = OidcUserService()
		return OAuth2UserService { userRequest ->
			val oidcUser = delegate.loadUser(userRequest)

			// JWT Access Token から roles を取得
			val accessToken = userRequest.accessToken.tokenValue
			val authorities = mutableSetOf<GrantedAuthority>()
			authorities.addAll(oidcUser.authorities)

			try {
				val claims = SignedJWT.parse(accessToken).jwtClaimsSet
				val roles = claims.getStringListClaim("roles") ?: emptyList()
				roles.forEach { role ->
					authorities.add(SimpleGrantedAuthority(role))
				}
			} catch (_: Exception) {
				// JWT のパースに失敗した場合は既存の authorities のみを使用
			}

			DefaultOidcUser(authorities, oidcUser.idToken, oidcUser.userInfo)
		}
	}

	@Bean
	fun securityFilterChain(
		http: HttpSecurity,
		clientRegistrationRepository: ClientRegistrationRepository,
		oidcUserService: OAuth2UserService<OidcUserRequest, OidcUser>
	): SecurityFilterChain {
		http
			.authorizeHttpRequests { authorize ->
				authorize
					.requestMatchers("/", "/index", "/webjars/**", "/assets/**", "/jwks", "/logged-out", "/api/initialize")
					.permitAll()
					.requestMatchers("/user-management/**").hasAuthority("ROLE_ADMIN")
					.anyRequest().authenticated()
			}
			.csrf { csrf -> csrf.ignoringRequestMatchers("/api/initialize") }
			.oauth2Login { oauth2Login ->
				oauth2Login
					.loginPage("/oauth2/authorization/gebo-client-oidc")
					.userInfoEndpoint { userInfo ->
						userInfo.oidcUserService(oidcUserService)
					}
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

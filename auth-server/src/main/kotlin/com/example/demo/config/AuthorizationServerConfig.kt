package com.example.demo.config

import com.example.demo.jose.Jwks
import com.example.demo.jose.RsaKeyLoader
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.JWKSelector
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.SecurityContext
import org.springframework.beans.factory.annotation.Value
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.annotation.Order
import org.springframework.http.MediaType
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.security.config.Customizer
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.core.oidc.OidcIdToken
import org.springframework.security.oauth2.core.oidc.OidcUserInfo
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationContext
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher
import java.security.Principal
import java.util.function.Function

@Configuration(proxyBeanMethods = false)
class AuthorizationServerConfig {

    @Value("\${app.oauth2.jwt.private-key:}")
    private var privateKeyPem: String = ""

    @Bean
    @Order(2)
    fun authorizationServerSecurityFilterChain(http: HttpSecurity): SecurityFilterChain {
        // TODO: 公式の参考
        // https://github.com/spring-projects/spring-security/blob/main/docs/modules/ROOT/pages/servlet/oauth2/authorization-server/getting-started.adoc

        http
            .oauth2AuthorizationServer { authorizationServer ->
                http.securityMatcher(authorizationServer.endpointsMatcher)          // TODO ここが気持ち悪い
                authorizationServer.authorizationEndpoint { endpoint ->
                    endpoint.consentPage("/oauth2/consent")
                }
                authorizationServer.oidc(Customizer.withDefaults())
            }
            .authorizeHttpRequests { authorize ->
                authorize.anyRequest().authenticated()
            }
            // Redirect to the /login page when not authenticated from the authorization endpoint
            // NOTE: DefaultSecurityConfig is configured with formLogin.loginPage("/login")
            .exceptionHandling { exceptions ->
                exceptions.defaultAuthenticationEntryPointFor(
                    LoginUrlAuthenticationEntryPoint("/login"),
                    MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                )
            }

        return http.build()
    }

    @Bean
    fun registeredClientRepository(jdbcTemplate: JdbcTemplate): JdbcRegisteredClientRepository {
        return JdbcRegisteredClientRepository(jdbcTemplate)
    }

    @Bean
    fun authorizationService(
        jdbcTemplate: JdbcTemplate,
        registeredClientRepository: RegisteredClientRepository
    ): JdbcOAuth2AuthorizationService {
        return JdbcOAuth2AuthorizationService(jdbcTemplate, registeredClientRepository)
    }

    @Bean
    fun authorizationConsentService(
        jdbcTemplate: JdbcTemplate,
        registeredClientRepository: RegisteredClientRepository
    ): JdbcOAuth2AuthorizationConsentService {
        // Will be used by the ConsentController
        return JdbcOAuth2AuthorizationConsentService(jdbcTemplate, registeredClientRepository)
    }

    @Bean
    fun jwkSource(): JWKSource<SecurityContext> {
        val rsaKey: RSAKey = if (privateKeyPem.isNotBlank()) {
            RsaKeyLoader.parsePemToRsaKey(privateKeyPem.trim())
        } else {
            Jwks.generateRsa()
        }
        val jwkSet = JWKSet(rsaKey)
        return JWKSource { jwkSelector: JWKSelector, securityContext: SecurityContext? -> jwkSelector.select(jwkSet) }
    }

    @Bean
    fun jwtDecoder(jwkSource: JWKSource<SecurityContext>): JwtDecoder {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource)
    }

    @Bean
    fun authorizationServerSettings(): AuthorizationServerSettings {
        return AuthorizationServerSettings.builder().build()
    }

    @Bean
    fun tokenCustomizer(): OAuth2TokenCustomizer<JwtEncodingContext> {
        return OAuth2TokenCustomizer { context ->
            if (context.tokenType.value == "access_token") {
                val principal = context.getPrincipal<Authentication>()
                // authorities には `FACTOR_PASSWORD` などの、どの認証方法を使ったかを示すマーカーも含まれるので、ROLEのみを抽出する
                val roles = principal.authorities
                    .map { it.authority }
                    .filter { it!!.startsWith("ROLE_") }
                    .toList()

                context.claims.claim("roles", roles)
            }
        }
    }

    @Bean
    fun userInfoMapper(): Function<OidcUserInfoAuthenticationContext, OidcUserInfo> {
        return Function { context ->
            val authentication = context.authorization.getAttribute<Authentication>(
                Principal::class.java.name
            )
            val roles = authentication?.authorities
                ?.map { it.authority }
                ?.filter { it!!.startsWith("ROLE_") }
                ?.toList() ?: emptyList()

            val idToken = context.authorization.getToken(OidcIdToken::class.java)
            val claims = idToken?.claims ?: emptyMap()

            OidcUserInfo.builder()
                .subject(context.authorization.principalName)
                .name(claims["name"] as? String)
                .givenName(claims["given_name"] as? String)
                .familyName(claims["family_name"] as? String)
                .email(claims["email"] as? String)
                .claim("roles", roles)
                .build()
        }
    }

}

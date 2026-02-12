package com.example.demo.config

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.annotation.Order
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.core.session.SessionRegistry
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.crypto.password.DelegatingPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.crypto.password.NoOpPasswordEncoder
import org.springframework.security.core.session.SessionRegistryImpl
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.session.HttpSessionEventPublisher

@EnableWebSecurity
@Configuration(proxyBeanMethods = false)
class DefaultSecurityConfig {
    /** /api/accounts は Authorization: Bearer トークンのみ（JWT の roles で ROLE_ADMIN を要求） */
    @Bean
    @Order(1)
    fun apiAccountsSecurityFilterChain(
        http: HttpSecurity,
        jwtDecoder: JwtDecoder
    ): SecurityFilterChain {
        val grantedAuthoritiesConverter = JwtGrantedAuthoritiesConverter().apply {
            setAuthoritiesClaimName("roles")
            setAuthorityPrefix("") // クレームがすでに "ROLE_ADMIN" 形式のためプレフィックス不要
        }
        val jwtAuthConverter = JwtAuthenticationConverter().apply {
            setJwtGrantedAuthoritiesConverter(grantedAuthoritiesConverter)
        }

        http
            .securityMatcher("/api/accounts")
            .authorizeHttpRequests { authorize ->
                authorize.anyRequest().authenticated()
            }
            .oauth2ResourceServer { resourceServer ->
                resourceServer.jwt { jwt ->
                    jwt.decoder(jwtDecoder).jwtAuthenticationConverter(jwtAuthConverter)
                }
            }
            .csrf { it.disable() }

        return http.build()
    }

    @Bean
    @Order(2)
    fun defaultSecurityFilterChain(http: HttpSecurity): SecurityFilterChain {
        http
            .authorizeHttpRequests { authorizeRequests ->
                authorizeRequests
                    .requestMatchers("/assets/**", "/login", "/api/initialize").permitAll()
                    .anyRequest().authenticated()
            }
            .formLogin { formLogin ->
                formLogin.loginPage("/login")
            }
            .csrf { csrf ->
                csrf.ignoringRequestMatchers("/api/initialize")
            }

        return http.build()
    }

    @Bean
    fun passwordEncoder(): PasswordEncoder {
        val idForEncode = "bcrypt"
        val bcrypt = BCryptPasswordEncoder()
        val encoders = mapOf(
            idForEncode to bcrypt,
            "noop" to NoOpPasswordEncoder.getInstance()
        )
        val delegating = DelegatingPasswordEncoder(idForEncode, encoders)
        // プレフィックスなしの既存パスワード（従来の BCrypt ハッシュ）も照合できるようにする
        return object : PasswordEncoder {
            override fun encode(rawPassword: CharSequence?): String =
                delegating.encode(rawPassword) ?: ""
            override fun matches(rawPassword: CharSequence?, encodedPassword: String?): Boolean {
                if (rawPassword == null || encodedPassword == null) return false
                return if (encodedPassword.startsWith("{")) {
                    delegating.matches(rawPassword, encodedPassword)
                } else {
                    bcrypt.matches(rawPassword, encodedPassword)
                }
            }
        }
    }

    @Bean
    fun sessionRegistry(): SessionRegistry {
        return SessionRegistryImpl()
    }

    @Bean
    fun httpSessionEventPublisher(): HttpSessionEventPublisher {
        return HttpSessionEventPublisher()
    }

}

package com.example.demo.config

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.annotation.Order
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.web.SecurityFilterChain

@Configuration(proxyBeanMethods = false)
class H2ConsoleSecurityConfig {
    @Bean
    @Order(1)
    fun h2consoleSecurityFilterChain(http: HttpSecurity): SecurityFilterChain {
        http
            .securityMatcher("/h2-console/**")
            .authorizeHttpRequests { authorizeRequests ->
                authorizeRequests
                    .anyRequest().permitAll()
            }
            .headers { headers ->
                headers.frameOptions { it.disable() }
            }
            .csrf { csrf ->
                csrf.disable()
            }

        return http.build()
    }

}

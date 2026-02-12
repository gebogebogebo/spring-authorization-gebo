package com.example.demo.web

import org.springframework.beans.factory.annotation.Value
import org.springframework.http.ResponseEntity
import org.springframework.stereotype.Controller
import org.springframework.ui.Model
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.client.RestClient
import org.springframework.web.client.RestClientResponseException

@Controller
class DefaultController(
    @Value("\${app.auth-server.url}")
    private val authServerUrl: String
) {
    @GetMapping("/")
    fun root(): String {
        return "redirect:/index"
    }

    @GetMapping("/index")
    fun index(model: Model): String {
        model.addAttribute("authServerUrl", authServerUrl)
        return "index"
    }

    @PostMapping("/api/initialize")
    fun initialize(): ResponseEntity<*> {
        return try {
            val response = RestClient.create()
                .post()
                .uri("$authServerUrl/api/initialize")
                .retrieve()
                .toEntity(Map::class.java)
            ResponseEntity.status(response.statusCode).body(response.body)
        } catch (e: RestClientResponseException) {
            ResponseEntity.status(e.statusCode).body(mapOf("error" to (e.responseBodyAsString.ifBlank { e.message })))
        }
    }
}

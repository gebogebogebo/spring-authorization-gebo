package com.example.demo.web

import org.springframework.http.ResponseEntity
import org.springframework.stereotype.Controller
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.client.RestClient
import org.springframework.web.client.RestClientResponseException

@Controller
class DefaultController {
    @GetMapping("/")
    fun root(): String {
        return "redirect:/index"
    }

    @GetMapping("/index")
    fun index(): String {
        return "index"
    }

    @PostMapping("/api/initialize")
    fun initialize(): ResponseEntity<*> {
        return try {
            val response = RestClient.create()
                .post()
                .uri("http://localhost:9000/api/initialize")
                .retrieve()
                .toEntity(Map::class.java)
            ResponseEntity.status(response.statusCode).body(response.body)
        } catch (e: RestClientResponseException) {
            ResponseEntity.status(e.statusCode).body(mapOf("error" to (e.responseBodyAsString.ifBlank { e.message })))
        }
    }
}

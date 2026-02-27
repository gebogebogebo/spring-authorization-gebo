package com.example.demo.web

import jakarta.servlet.http.HttpSession
import org.springframework.security.core.Authentication
import org.springframework.stereotype.Controller
import org.springframework.ui.Model
import org.springframework.web.bind.annotation.GetMapping
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter

@Controller
class HomeController {
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

        model.addAttribute("sessionId", session.id)
        model.addAttribute("sessionCreatedAt", createdAt)
        model.addAttribute("sessionLastAccessedAt", lastAccessedAt)
        model.addAttribute("sessionTtlSeconds", ttlSeconds)
        model.addAttribute("username", username)
        model.addAttribute("authorities", authorities)
        return "home"
    }
}

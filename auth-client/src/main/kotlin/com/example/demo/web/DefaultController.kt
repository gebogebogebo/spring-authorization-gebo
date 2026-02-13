package com.example.demo.web

import org.springframework.beans.factory.annotation.Value
import org.springframework.stereotype.Controller
import org.springframework.ui.Model
import org.springframework.web.bind.annotation.GetMapping

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
}

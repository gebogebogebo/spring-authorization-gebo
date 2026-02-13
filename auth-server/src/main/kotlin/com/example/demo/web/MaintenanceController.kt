package com.example.demo.web

import org.springframework.stereotype.Controller
import org.springframework.web.bind.annotation.GetMapping

@Controller
class MaintenanceController {

    @GetMapping("/maintenance")
    fun maintenance(): String = "maintenance"
}

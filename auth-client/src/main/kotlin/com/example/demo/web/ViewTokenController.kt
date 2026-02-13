package com.example.demo.web

import com.example.demo.service.OidcTokenService
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken
import org.springframework.stereotype.Controller
import org.springframework.ui.Model
import org.springframework.web.bind.annotation.GetMapping

@Controller
class ViewTokenController(
    private val oidcTokenService: OidcTokenService
) {
    @GetMapping("/view-token")
    fun viewToken(
        model: Model,
        authentication: OAuth2AuthenticationToken?
    ): String {
        val accessTokenValue = oidcTokenService.getAccessTokenValue(authentication)
        val decodedToken = oidcTokenService.getDecodedJwt(authentication)
        model.addAttribute("accessToken", accessTokenValue)
        model.addAttribute("accessTokenHeader", decodedToken?.header)
        model.addAttribute("accessTokenPayload", decodedToken?.payload)
        model.addAttribute("accessTokenExpJst", decodedToken?.expJst)
        model.addAttribute("accessTokenIatJst", decodedToken?.iatJst)
        model.addAttribute("accessTokenExpired", decodedToken?.expired ?: false)
        return "view-token"
    }
}

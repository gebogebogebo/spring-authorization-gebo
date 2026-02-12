package com.example.demo.service

import com.nimbusds.jwt.SignedJWT
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken
import org.springframework.stereotype.Service
import tools.jackson.databind.ObjectMapper
import java.time.ZoneId
import java.time.format.DateTimeFormatter

@Service
class OidcTokenService(
    private val authorizedClientService: OAuth2AuthorizedClientService
) {
    data class DecodedJwt(
        val header: String,
        val payload: String,
        val expJst: String?,
        val iatJst: String?
    )

    private val objectMapper = ObjectMapper()
    private val jstZoneId = ZoneId.of("Asia/Tokyo")
    private val jstFormatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss XXX")

    fun getDecodedJwt(authentication: OAuth2AuthenticationToken?): DecodedJwt? {
        val accessTokenValue = getAccessTokenValue(authentication)
        return accessTokenValue?.let { decodeJwt(it) }
    }

    fun getAccessTokenValue(authentication: OAuth2AuthenticationToken?): String? {
        val authorizedClient: OAuth2AuthorizedClient? = authentication?.let {
            authorizedClientService.loadAuthorizedClient(
                it.authorizedClientRegistrationId,
                it.name
            )
        }
        return authorizedClient?.accessToken?.tokenValue
    }

    private fun decodeJwt(tokenValue: String): DecodedJwt? {
        return try {
            val signedJwt = SignedJWT.parse(tokenValue)
            val writer = objectMapper.writerWithDefaultPrettyPrinter()
            val headerJson = writer.writeValueAsString(signedJwt.header.toJSONObject())
            val payloadJson = writer.writeValueAsString(signedJwt.jwtClaimsSet.toJSONObject())
            val expJst = signedJwt.jwtClaimsSet.expirationTime?.toInstant()
                ?.atZone(jstZoneId)
                ?.format(jstFormatter)
            val iatJst = signedJwt.jwtClaimsSet.issueTime?.toInstant()
                ?.atZone(jstZoneId)
                ?.format(jstFormatter)
            DecodedJwt(headerJson, payloadJson, expJst, iatJst)
        } catch (ex: Exception) {
            null
        }
    }
}

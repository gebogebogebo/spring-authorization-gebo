package com.example.demo.service

import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService
import org.springframework.security.oauth2.client.registration.ClientRegistration
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository
import org.springframework.util.Assert
import org.springframework.web.context.request.RequestContextHolder
import org.springframework.web.context.request.ServletRequestAttributes
import jakarta.servlet.http.HttpSession

/**
 * [OAuth2AuthorizedClientService] の実装で、認可済みクライアントを HTTP セッションに保存する。
 * [InMemoryOAuth2AuthorizedClientService] と同様の API だが、ストレージに [HttpSession] を使用する。
 *
 * セッション外（バックグラウンドスレッド等）から呼ばれた場合はセッションを取得できないため、
 * load は null、save/remove は何もしない。
 */
class HttpSessionOAuth2AuthorizedClientService(
    private val clientRegistrationRepository: ClientRegistrationRepository
) : OAuth2AuthorizedClientService {

    @Suppress("UNCHECKED_CAST")
    override fun <T : OAuth2AuthorizedClient> loadAuthorizedClient(clientRegistrationId: String, principalName: String): T? {
        Assert.hasText(clientRegistrationId, "clientRegistrationId cannot be empty")
        Assert.hasText(principalName, "principalName cannot be empty")
        val registration = clientRegistrationRepository.findByRegistrationId(clientRegistrationId)
            ?: return null
        val session = getSession(create = false) ?: return null
        @Suppress("UNCHECKED_CAST")
        val map = session.getAttribute(SESSION_ATTR_AUTHORIZED_CLIENTS) as? MutableMap<String, OAuth2AuthorizedClient>
            ?: return null
        val cached = map[toMapKey(clientRegistrationId, principalName)] ?: return null
        return OAuth2AuthorizedClient(
            registration,
            cached.principalName,
            cached.accessToken,
            cached.refreshToken
        ) as T
    }

    override fun saveAuthorizedClient(authorizedClient: OAuth2AuthorizedClient, principal: Authentication) {
        Assert.notNull(authorizedClient, "authorizedClient cannot be null")
        Assert.notNull(principal, "principal cannot be null")
        val session = getSession(create = true) ?: return
        @Suppress("UNCHECKED_CAST")
        val map = session.getAttribute(SESSION_ATTR_AUTHORIZED_CLIENTS) as? MutableMap<String, OAuth2AuthorizedClient>
            ?: mutableMapOf<String, OAuth2AuthorizedClient>().also { session.setAttribute(SESSION_ATTR_AUTHORIZED_CLIENTS, it) }
        val key = toMapKey(
            authorizedClient.clientRegistration.registrationId,
            principal.name ?: return
        )
        map[key] = authorizedClient
    }

    override fun removeAuthorizedClient(clientRegistrationId: String, principalName: String) {
        Assert.hasText(clientRegistrationId, "clientRegistrationId cannot be empty")
        Assert.hasText(principalName, "principalName cannot be empty")
        val session = getSession(create = false) ?: return
        @Suppress("UNCHECKED_CAST")
        val map = session.getAttribute(SESSION_ATTR_AUTHORIZED_CLIENTS) as? MutableMap<String, OAuth2AuthorizedClient>
            ?: return
        map.remove(toMapKey(clientRegistrationId, principalName))
    }

    private fun getSession(create: Boolean = false): HttpSession? {
        val attrs = RequestContextHolder.getRequestAttributes() as? ServletRequestAttributes ?: return null
        return attrs.request.getSession(create)
    }

    private fun toMapKey(clientRegistrationId: String, principalName: String): String =
        "$clientRegistrationId::$principalName"

    companion object {
        private const val SESSION_ATTR_AUTHORIZED_CLIENTS = "oauth2_authorized_clients"
    }
}

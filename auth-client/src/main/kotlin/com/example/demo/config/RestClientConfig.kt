package com.example.demo.config

import org.apache.hc.client5.http.impl.classic.HttpClients
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder
import org.apache.hc.client5.http.ssl.NoopHostnameVerifier
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactory
import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.boot.ssl.SslBundle
import org.springframework.boot.ssl.SslBundles
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.client.ClientHttpRequestFactory
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory
import org.springframework.http.converter.FormHttpMessageConverter
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager
import org.springframework.security.oauth2.client.endpoint.DefaultOAuth2TokenRequestParametersConverter
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient
import org.springframework.security.oauth2.client.endpoint.OAuth2ClientCredentialsGrantRequest
import org.springframework.security.oauth2.client.endpoint.RestClientClientCredentialsTokenResponseClient
import org.springframework.security.oauth2.client.http.OAuth2ErrorResponseErrorHandler
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository
import org.springframework.security.oauth2.client.web.client.OAuth2ClientHttpRequestInterceptor
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter
import org.springframework.web.client.RestClient
import java.util.function.Supplier
import javax.net.ssl.SSLContext

@Configuration(proxyBeanMethods = false)
class RestClientConfig {

	@Bean("default-client-rest-client")
	fun defaultClientRestClient(
        authorizedClientRepository: OAuth2AuthorizedClientRepository,
        authorizedClientManager: OAuth2AuthorizedClientManager,
        @Qualifier("default-client-http-request-factory")
		clientHttpRequestFactory: Supplier<ClientHttpRequestFactory>
	): RestClient {
		val requestInterceptor = OAuth2ClientHttpRequestInterceptor(authorizedClientManager)
		val authorizationFailureHandler =
			OAuth2ClientHttpRequestInterceptor.authorizationFailureHandler(authorizedClientRepository)
		requestInterceptor.setAuthorizationFailureHandler(authorizationFailureHandler)

		return RestClient.builder()
			.requestFactory(clientHttpRequestFactory.get())
			.requestInterceptor(requestInterceptor)
			.build()
	}

	@Bean("default-client-http-request-factory")
	fun defaultClientHttpRequestFactory(sslBundles: SslBundles): Supplier<ClientHttpRequestFactory> {
		return Supplier {
			val sslBundle: SslBundle = sslBundles.getBundle("gebo-client")
			val sslContext: SSLContext = sslBundle.createSslContext()
			val sslConnectionSocketFactory =
				SSLConnectionSocketFactory(sslContext, NoopHostnameVerifier.INSTANCE)
			val connectionManager = PoolingHttpClientConnectionManagerBuilder.create()
				.setSSLSocketFactory(sslConnectionSocketFactory)
				.build()
			val httpClient = HttpClients.custom()
				.setConnectionManager(connectionManager)
				.build()
			HttpComponentsClientHttpRequestFactory(httpClient)
		}
	}


	private fun accessTokenRestClient(
		clientHttpRequestFactory: Supplier<ClientHttpRequestFactory>
	): RestClient {
		return RestClient.builder()
			.requestFactory(clientHttpRequestFactory.get())
			.messageConverters { messageConverters ->
				messageConverters.clear()
				messageConverters.add(FormHttpMessageConverter())
				messageConverters.add(OAuth2AccessTokenResponseHttpMessageConverter())
			}
			.defaultStatusHandler(OAuth2ErrorResponseErrorHandler())
			.build()
	}

	private fun createClientCredentialsTokenResponseClient(
		restClient: RestClient
	): OAuth2AccessTokenResponseClient<OAuth2ClientCredentialsGrantRequest> {
		val clientCredentialsTokenResponseClient = RestClientClientCredentialsTokenResponseClient()
		clientCredentialsTokenResponseClient.setParametersConverter(
			DefaultOAuth2TokenRequestParametersConverter()
		)
		clientCredentialsTokenResponseClient.setRestClient(restClient)

		return clientCredentialsTokenResponseClient
	}
}

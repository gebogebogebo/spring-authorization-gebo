package com.example.demo.jose

import com.nimbusds.jose.jwk.RSAKey
import java.security.KeyFactory
import java.security.interfaces.RSAPrivateCrtKey
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.RSAPublicKeySpec
import java.util.Base64

/**
 * PEM 形式（PKCS#8）の RSA 秘密鍵から [RSAKey] を組み立てる。
 * Java 標準 API のみ使用（Bouncy Castle 不要）。
 *
 * 対応形式: -----BEGIN PRIVATE KEY----- ... -----END PRIVATE KEY-----
 * openssl genrsa の出力を使う場合は、事前に PKCS#8 へ変換する:
 *   openssl pkcs8 -topk8 -inform PEM -outform PEM -in jwt-key.pem -nocrypt
 */
object RsaKeyLoader {

    private const val PEM_HEADER = "-----BEGIN PRIVATE KEY-----"
    private const val PEM_FOOTER = "-----END PRIVATE KEY-----"
    private const val KEY_ID = "oauth2-jwt-key"

    /**
     * PEM 文字列（改行含む）をパースして [RSAKey] を返す。
     */
    fun parsePemToRsaKey(pemContent: String): RSAKey {
        val privateKey = parsePemToPrivateKey(pemContent.trim())
        val publicKey = derivePublicKey(privateKey)
        return RSAKey.Builder(publicKey)
            .privateKey(privateKey)
            .keyID(KEY_ID)
            .build()
    }

    private fun parsePemToPrivateKey(pemContent: String): java.security.interfaces.RSAPrivateKey {
        val content = pemContent
            .replace(PEM_HEADER, "")
            .replace(PEM_FOOTER, "")
            .replace("\\s".toRegex(), "")
        val keyBytes = Base64.getDecoder().decode(content)
        val spec = PKCS8EncodedKeySpec(keyBytes)
        val kf = KeyFactory.getInstance("RSA")
        return kf.generatePrivate(spec) as java.security.interfaces.RSAPrivateKey
    }

    private fun derivePublicKey(privateKey: java.security.interfaces.RSAPrivateKey): java.security.interfaces.RSAPublicKey {
        val crtKey = privateKey as? RSAPrivateCrtKey
            ?: throw IllegalArgumentException("RSAPrivateCrtKey required to derive public key")
        val spec = RSAPublicKeySpec(crtKey.modulus, crtKey.publicExponent)
        val kf = KeyFactory.getInstance("RSA")
        return kf.generatePublic(spec) as java.security.interfaces.RSAPublicKey
    }
}

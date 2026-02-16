package com.example.demo.jose

import com.nimbusds.jose.jwk.RSAKey
import org.bouncycastle.openssl.PEMKeyPair
import org.bouncycastle.openssl.PEMParser
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter
import java.io.StringReader
import java.security.KeyFactory
import java.security.interfaces.RSAPrivateCrtKey
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.RSAPublicKeySpec
import java.util.Base64

/**
 * PEM 形式の RSA 秘密鍵から [RSAKey] を組み立てる。
 * 対応形式:
 * - PKCS#1: -----BEGIN RSA PRIVATE KEY----- (openssl genrsa の出力)
 * - PKCS#8: -----BEGIN PRIVATE KEY-----
 */
object RsaKeyLoader {

    private const val PEM_HEADER_PKCS8 = "-----BEGIN PRIVATE KEY-----"
    private const val PEM_FOOTER_PKCS8 = "-----END PRIVATE KEY-----"
    private const val KEY_ID = "oauth2-jwt-key"

    /**
     * PEM 文字列（改行含む）をパースして [RSAKey] を返す。
     */
    fun parsePemToRsaKey(pemContent: String): RSAKey {
        val trimmed = pemContent.trim()
        return when {
            trimmed.contains("BEGIN RSA PRIVATE KEY") || trimmed.contains("BEGIN PRIVATE KEY") ->
                parseWithBouncyCastle(trimmed)
            trimmed.contains(PEM_HEADER_PKCS8) ->
                parsePkcs8ToRsaKey(trimmed)
            else ->
                throw IllegalArgumentException("Unsupported PEM format: expected RSA PRIVATE KEY or PRIVATE KEY")
        }
    }

    /** Bouncy Castle で PKCS#1 または PKCS#8 を読み、RSAKey を返す。 */
    private fun parseWithBouncyCastle(pemContent: String): RSAKey {
        PEMParser(StringReader(pemContent)).use { parser ->
            val converter = JcaPEMKeyConverter()
            when (val obj = parser.readObject()) {
                is PEMKeyPair -> {
                    val keyPair = converter.getKeyPair(obj)
                    val publicKey = keyPair.public as java.security.interfaces.RSAPublicKey
                    val privateKey = keyPair.private as java.security.interfaces.RSAPrivateKey
                    return RSAKey.Builder(publicKey)
                        .privateKey(privateKey)
                        .keyID(KEY_ID)
                        .build()
                }
                is org.bouncycastle.asn1.pkcs.PrivateKeyInfo -> {
                    val privateKey = converter.getPrivateKey(obj) as java.security.interfaces.RSAPrivateKey
                    val publicKey = derivePublicKey(privateKey)
                    return RSAKey.Builder(publicKey)
                        .privateKey(privateKey)
                        .keyID(KEY_ID)
                        .build()
                }
                else -> throw IllegalArgumentException("Unsupported PEM object: ${obj?.javaClass?.name}")
            }
        }
    }

    /** PKCS#8 のみ Java 標準でパース（Bouncy に依存しないフォールバック）。 */
    private fun parsePkcs8ToRsaKey(pemContent: String): RSAKey {
        val privateKey = parsePemToPrivateKeyPkcs8(pemContent)
        val publicKey = derivePublicKey(privateKey)
        return RSAKey.Builder(publicKey)
            .privateKey(privateKey)
            .keyID(KEY_ID)
            .build()
    }

    private fun parsePemToPrivateKeyPkcs8(pemContent: String): java.security.interfaces.RSAPrivateKey {
        val content = pemContent
            .replace(PEM_HEADER_PKCS8, "")
            .replace(PEM_FOOTER_PKCS8, "")
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

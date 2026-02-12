package com.example.demo.jose

import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.OctetSequenceKey
import com.nimbusds.jose.jwk.RSAKey
import java.security.KeyPair
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.util.UUID
import javax.crypto.SecretKey

object Jwks {
    fun generateRsa(): RSAKey {
        val keyPair: KeyPair = KeyGeneratorUtils.generateRsaKey()
        val publicKey = keyPair.getPublic() as RSAPublicKey
        val privateKey = keyPair.getPrivate() as RSAPrivateKey
        return RSAKey.Builder(publicKey)
            .privateKey(privateKey)
            .keyID(UUID.randomUUID().toString())
            .build()
    }

    fun generateEc(): ECKey {
        val keyPair: KeyPair = KeyGeneratorUtils.generateEcKey()
        val publicKey = keyPair.getPublic() as ECPublicKey
        val privateKey = keyPair.getPrivate() as ECPrivateKey
        val curve = Curve.forECParameterSpec(publicKey.getParams())
        return ECKey.Builder(curve, publicKey)
            .privateKey(privateKey)
            .keyID(UUID.randomUUID().toString())
            .build()
    }

    fun generateSecret(): OctetSequenceKey? {
        val secretKey: SecretKey = KeyGeneratorUtils.generateSecretKey()
        return OctetSequenceKey.Builder(secretKey)
            .keyID(UUID.randomUUID().toString())
            .build()
    }
}

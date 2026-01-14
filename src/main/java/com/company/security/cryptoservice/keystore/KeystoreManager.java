package com.company.security.cryptoservice.keystore;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;

@Component
public class KeystoreManager {

    @Value("${crypto.keystore.password}")
    private String keystorePassword;

    @Value("${crypto.keystore.type}")
    private String keystoreType;

    private static final String KEYSTORE_FILE = "com/company/security/cryptoservice/keystore/keystore.jks";

    //  Public key → encryption
    public PublicKey getPublicKey(String alias) {
        try {
            KeyStore keyStore = loadKeyStore();
            return keyStore.getCertificate(alias).getPublicKey();
        } catch (Exception e) {
            throw new RuntimeException("Unable to load public key", e);
        }
    }

    //  Private key → decryption
    public PrivateKey getPrivateKey(String alias) {
        try {
            KeyStore keyStore = loadKeyStore();
            return (PrivateKey) keyStore.getKey(
                    alias,
                    keystorePassword.toCharArray()
            );
        } catch (Exception e) {
            throw new RuntimeException("Unable to load private key", e);
        }
    }

    //  Common keystore loader
    private KeyStore loadKeyStore() throws Exception {
        KeyStore keyStore = KeyStore.getInstance(keystoreType);

        InputStream is = getClass()
                .getClassLoader()
                .getResourceAsStream(KEYSTORE_FILE);

        if (is == null) {
            throw new RuntimeException("keystore.jks not found in resources");
        }

        keyStore.load(is, keystorePassword.toCharArray());
        return keyStore;
    }
}

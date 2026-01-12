package com.company.security.cryptoservice.keystore;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.io.InputStream;
import java.security.KeyStore;

@Component
public class KeystoreManager {

    @Value("${crypto.keystore.password}")
    private String keystorePassword;

    @Value("${crypto.keystore.type}")
    private String keystoreType;

    public SecretKey getSecretKey(String alias) {
        try {
            KeyStore keyStore = KeyStore.getInstance(keystoreType);

            InputStream is = getClass()
                    .getClassLoader()
                    .getResourceAsStream("keystore.p12");

            if (is == null) {
                throw new RuntimeException("keystore.p12 not found in resources");
            }

            keyStore.load(is, keystorePassword.toCharArray());

            return (SecretKey) keyStore.getKey(
                    alias,
                    keystorePassword.toCharArray()
            );

        } catch (Exception e) {
            throw new RuntimeException("Unable to load key from keystore", e);
        }
    }
}

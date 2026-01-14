package com.company.security.cryptoservice.keystore;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.PrivateKey;

@Component
public class KeystoreManager {

    @Value("${crypto.keystore.path}")
    private String keystorePath;

    @Value("${crypto.keystore.password}")
    private String keystorePassword;

    @Value("${crypto.keystore.type}")
    private String keystoreType;

    public PrivateKey getPrivateKey(String alias) {
        try {
            KeyStore ks = loadKeystore();
            return (PrivateKey) ks.getKey(
                    alias,
                    keystorePassword.toCharArray()
            );
        } catch (Exception e) {
            throw new RuntimeException("Private key load failed");
        }
    }

    public SecretKey getSecretKey(String alias) {
        try {
            KeyStore ks = loadKeystore();

            KeyStore.SecretKeyEntry entry =
                    (KeyStore.SecretKeyEntry) ks.getEntry(
                            alias,
                            new KeyStore.PasswordProtection(
                                    keystorePassword.toCharArray()
                            )
                    );

            return entry.getSecretKey();
        } catch (Exception e) {
            throw new RuntimeException("AES key load failed");
        }
    }

    private KeyStore loadKeystore() throws Exception {
        KeyStore ks = KeyStore.getInstance(keystoreType);
        try (InputStream is =
                     Files.newInputStream(Path.of(keystorePath))) {
            ks.load(is, keystorePassword.toCharArray());
        }
        return ks;
    }
}

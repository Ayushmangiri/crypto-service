package com.company.security.cryptoservice.keystore;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.PrivateKey;

@Component
public class KeystoreManager {
    @Value("${crypto.keystore.path}") private String keystorePath;
    @Value("${crypto.keystore.password}") private String keystorePassword;
    @Value("${crypto.keystore.type}") private String keystoreType;

    public PrivateKey getPrivateKey(String alias) {
        try {
            KeyStore ks = KeyStore.getInstance(keystoreType);
            try (InputStream is = Files.newInputStream(Path.of(keystorePath))) {
                ks.load(is, keystorePassword.toCharArray());
            }
            PrivateKey key = (PrivateKey) ks.getKey(alias, keystorePassword.toCharArray());
            if (key == null) throw new RuntimeException("Alias not found: " + alias);
            return key;
        } catch (Exception e) {
            throw new RuntimeException("Keystore Error: " + e.getMessage());
        }
    }
}
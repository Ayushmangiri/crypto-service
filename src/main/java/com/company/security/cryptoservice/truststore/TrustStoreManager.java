package com.company.security.cryptoservice.truststore;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.X509Certificate;

@Component
public class TrustStoreManager {
    @Value("${crypto.truststore.path}") private String path;
    @Value("${crypto.truststore.password}") private String password;
    @Value("${crypto.truststore.type}") private String type;

    public X509Certificate getCert(String alias) {
        try {
            KeyStore ts = KeyStore.getInstance(type);
            try (InputStream is = Files.newInputStream(Path.of(path))) {
                ts.load(is, password.toCharArray());
            }
            X509Certificate cert = (X509Certificate) ts.getCertificate(alias);
            if (cert == null) throw new RuntimeException("Alias not found in TrustStore: " + alias);
            return cert;
        } catch (Exception e) {
            throw new RuntimeException("Trust verification failed: " + e.getMessage());
        }
    }
}
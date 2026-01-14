package com.company.security.cryptoservice.utility;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.FileOutputStream;
import java.security.KeyStore;

public class AddAesKeyToKeystore {

    public static void main(String[] args) throws Exception {

        String keystorePath =
                "C:/Users/ayush/OneDrive/Desktop/Projects/crypto-service/crypto-service/src/main/java/com/company/security/cryptoservice/keystore/keystore.jks";

        String password = "password";

        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(
                new java.io.FileInputStream(keystorePath),
                password.toCharArray()
        );

        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey aesKey = keyGen.generateKey();

        KeyStore.SecretKeyEntry entry =
                new KeyStore.SecretKeyEntry(aesKey);

        ks.setEntry(
                "aes-key-alias",
                entry,
                new KeyStore.PasswordProtection(password.toCharArray())
        );

        try (FileOutputStream fos =
                     new FileOutputStream(keystorePath)) {
            ks.store(fos, password.toCharArray());
        }

        System.out.println("AES key added successfully");
    }
}

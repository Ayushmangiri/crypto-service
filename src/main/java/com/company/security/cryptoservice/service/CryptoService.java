package com.company.security.cryptoservice.service;

import com.company.security.cryptoservice.keystore.KeystoreManager;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import java.util.Base64;

@Service
public class CryptoService {

    private final KeystoreManager keystoreManager;

    public CryptoService(KeystoreManager keystoreManager) {
        this.keystoreManager = keystoreManager;
    }

    public String encrypt(String alias, String plainText) {
        try {
            SecretKey key = keystoreManager.getSecretKey(alias);

            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, key);

            byte[] encrypted = cipher.doFinal(plainText.getBytes());
            return Base64.getEncoder().encodeToString(encrypted);

        } catch (Exception e) {
            throw new RuntimeException("Encryption failed", e);
        }
    }

    public String decrypt(String alias, String encryptedText) {
        try {
            SecretKey key = keystoreManager.getSecretKey(alias);

            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, key);

            byte[] decoded = Base64.getDecoder().decode(encryptedText);
            return new String(cipher.doFinal(decoded));

        } catch (Exception e) {
            throw new RuntimeException("Decryption failed", e);
        }
    }
}

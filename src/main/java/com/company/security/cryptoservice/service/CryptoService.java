package com.company.security.cryptoservice.service;

import com.company.security.cryptoservice.keystore.KeystoreManager;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

@Service
public class CryptoService {

    private final KeystoreManager keystoreManager;

    public CryptoService(KeystoreManager keystoreManager) {
        this.keystoreManager = keystoreManager;
    }

    public String encrypt(String alias, String plainText) {
        try {
            PublicKey publicKey = keystoreManager.getPublicKey(alias);

            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);

            byte[] encrypted = cipher.doFinal(plainText.getBytes());
            return Base64.getEncoder().encodeToString(encrypted);

        } catch (Exception e) {
            throw new RuntimeException("RSA Encryption failed", e);
        }
    }


    public String decrypt(String alias, String encryptedText) {
        try {
            PrivateKey privateKey = keystoreManager.getPrivateKey(alias);

            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);

            byte[] decoded = Base64.getDecoder().decode(encryptedText);
            return new String(cipher.doFinal(decoded));

        } catch (Exception e) {
            throw new RuntimeException("RSA Decryption failed", e);
        }
    }
}

package com.company.security.cryptoservice.service;

import com.company.security.cryptoservice.keystore.KeystoreManager;
import com.company.security.cryptoservice.truststore.TrustStoreManager;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import javax.crypto.Cipher;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import java.util.HexFormat;

@Service
public class CryptoService {
    private final TrustStoreManager trustStoreManager;
    private final KeystoreManager keystoreManager;

    @Value("${crypto.aes.key}") private String aesKeyHex;
    @Value("${crypto.aes.iv}") private String ivHex;

    public CryptoService(TrustStoreManager trustStoreManager, KeystoreManager keystoreManager) {
        this.trustStoreManager = trustStoreManager;
        this.keystoreManager = keystoreManager;
    }

    public String encrypt(String certAlias, String plainText) {
        try {
            PublicKey publicKey = trustStoreManager.getCert(certAlias).getPublicKey();
            Cipher rsa = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsa.init(Cipher.ENCRYPT_MODE, publicKey);

            byte[] wrappedKey = rsa.doFinal(HexFormat.of().parseHex(aesKeyHex));
            String encryptedAesKeyBase64 = Base64.getEncoder().encodeToString(wrappedKey);

            System.out.println("\n==================================================");
            System.out.println("USE THIS AS 'encryptedAesKey' IN DECRYPT REQUEST:");
            System.out.println(encryptedAesKeyBase64);
            System.out.println("==================================================\n");

            // 2. AES se data encrypt karna
            byte[] encryptedData = Aes256Util.encrypt(plainText.getBytes(), aesKeyHex, ivHex);
            return Base64.getEncoder().encodeToString(encryptedData);
        } catch (Exception e) {
            throw new RuntimeException("Encryption Error: " + e.getMessage());
        }
    }

    public String decrypt(String certAlias, String encryptedAesKeyBase64, String encryptedDataBase64, String ivHexFromReq) {
        try {
            PrivateKey privateKey = keystoreManager.getPrivateKey(certAlias);
            Cipher rsa = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsa.init(Cipher.DECRYPT_MODE, privateKey);

            byte[] aesKeyBytes = rsa.doFinal(Base64.getDecoder().decode(encryptedAesKeyBase64));
            String decryptedAesKeyHex = HexFormat.of().formatHex(aesKeyBytes);

            byte[] plainBytes = Aes256Util.decrypt(
                    Base64.getDecoder().decode(encryptedDataBase64),
                    decryptedAesKeyHex,
                    ivHexFromReq
            );

            return new String(plainBytes);
        } catch (Exception e) {
            throw new RuntimeException("Decryption failed: RSA Key unwrap issue or wrong Alias.");
        }
    }
}
package com.company.security.cryptoservice.service;

import com.company.security.cryptoservice.keystore.KeystoreManager;
import com.company.security.cryptoservice.truststore.TrustStoreManager;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HexFormat;

@Service
public class CryptoService {

    private final TrustStoreManager trustStoreManager;
    private final KeystoreManager keystoreManager;

    public CryptoService(
            TrustStoreManager trustStoreManager,
            KeystoreManager keystoreManager
    ) {
        this.trustStoreManager = trustStoreManager;
        this.keystoreManager = keystoreManager;
    }
    public String encrypt(String certAlias, String plainText) {
        try {
            SecretKey aesKey =
                    keystoreManager.getSecretKey("aes-key-alias");

            byte[] iv = new byte[16];
            new SecureRandom().nextBytes(iv);

            byte[] encryptedData =
                    AesUtil.encrypt(
                            plainText.getBytes(StandardCharsets.UTF_8),
                            aesKey,
                            iv
                    );

            PublicKey publicKey =
                    trustStoreManager
                            .getCert(certAlias)
                            .getPublicKey();

            Cipher rsa =
                    Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsa.init(Cipher.ENCRYPT_MODE, publicKey);

            byte[] encryptedAesKey =
                    rsa.doFinal(aesKey.getEncoded());

            System.out.println("encryptedAesKey = "
                    + Base64.getEncoder()
                    .encodeToString(encryptedAesKey));

            System.out.println("ivHex = "
                    + HexFormat.of().formatHex(iv));

            return Base64.getEncoder()
                    .encodeToString(encryptedData);

        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException("Encryption failed", e);
        }
    }

    public String decrypt(
            String certAlias,
            String encryptedAesKeyBase64,
            String encryptedDataBase64,
            String ivHex
    ) {
        try {
            PrivateKey privateKey =
                    keystoreManager.getPrivateKey(certAlias);

            Cipher rsa =
                    Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsa.init(Cipher.DECRYPT_MODE, privateKey);

            byte[] aesKeyBytes =
                    rsa.doFinal(
                            Base64.getDecoder()
                                    .decode(encryptedAesKeyBase64)
                    );

            SecretKey aesKey =
                    new SecretKeySpec(aesKeyBytes, "AES");

            byte[] plain =
                    AesUtil.decrypt(
                            Base64.getDecoder()
                                    .decode(encryptedDataBase64),
                            aesKey,
                            HexFormat.of().parseHex(ivHex)
                    );

            return new String(plain, StandardCharsets.UTF_8);

        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException("Decryption failed", e);
        }
    }
}

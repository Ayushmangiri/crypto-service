package com.company.security.cryptoservice.service;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class AesUtil {

    public static byte[] encrypt(
            byte[] plain,
            SecretKey key,
            byte[] iv
    ) throws Exception {

        Cipher cipher =
                Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(
                Cipher.ENCRYPT_MODE,
                key,
                new IvParameterSpec(iv)
        );
        return cipher.doFinal(plain);
    }

    public static byte[] decrypt(
            byte[] encrypted,
            SecretKey key,
            byte[] iv
    ) throws Exception {

        Cipher cipher =
                Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(
                Cipher.DECRYPT_MODE,
                key,
                new IvParameterSpec(iv)
        );
        return cipher.doFinal(encrypted);
    }
}

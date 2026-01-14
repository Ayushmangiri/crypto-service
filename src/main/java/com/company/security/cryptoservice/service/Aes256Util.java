package com.company.security.cryptoservice.service;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.HexFormat;

public class Aes256Util {
    public static byte[] encrypt(byte[] data, String hexKey, String hexIv) throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(HexFormat.of().parseHex(hexKey), "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(HexFormat.of().parseHex(hexIv));
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        return cipher.doFinal(data);
    }

    public static byte[] decrypt(byte[] encrypted, String hexKey, String hexIv) throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(HexFormat.of().parseHex(hexKey), "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(HexFormat.of().parseHex(hexIv));
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
        return cipher.doFinal(encrypted);
    }
}
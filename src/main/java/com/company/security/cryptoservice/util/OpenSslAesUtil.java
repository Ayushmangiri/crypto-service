package com.company.security.cryptoservice.util;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.HexFormat;

public class OpenSslAesUtil {

    public static byte[] encrypt(
            byte[] plain,
            String hexKey,
            String hexIv
    ) throws Exception {

        SecretKey key = new SecretKeySpec(
                HexFormat.of().parseHex(hexKey),
                "AES"
        );

        IvParameterSpec iv = new IvParameterSpec(
                HexFormat.of().parseHex(hexIv)
        );

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);

        return cipher.doFinal(plain);
    }

    public static byte[] decrypt(
            byte[] encrypted,
            String hexKey,
            String hexIv
    ) throws Exception {

        SecretKey key = new SecretKeySpec(
                HexFormat.of().parseHex(hexKey),
                "AES"
        );

        IvParameterSpec iv = new IvParameterSpec(
                HexFormat.of().parseHex(hexIv)
        );

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key, iv);

        return cipher.doFinal(encrypted);
    }
}

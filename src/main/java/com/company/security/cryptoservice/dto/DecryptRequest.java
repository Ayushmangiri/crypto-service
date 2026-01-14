package com.company.security.cryptoservice.dto;

public class DecryptRequest {

    private String certAlias;

    private String encryptedAesKey;

    private String encryptedData;

    private String ivHex;

    public String getCertAlias() {
        return certAlias;
    }

    public void setCertAlias(String certAlias) {
        this.certAlias = certAlias;
    }

    public String getEncryptedAesKey() {
        return encryptedAesKey;
    }

    public void setEncryptedAesKey(String encryptedAesKey) {
        this.encryptedAesKey = encryptedAesKey;
    }

    public String getEncryptedData() {
        return encryptedData;
    }

    public void setEncryptedData(String encryptedData) {
        this.encryptedData = encryptedData;
    }

    public String getIvHex() {
        return ivHex;
    }

    public void setIvHex(String ivHex) {
        this.ivHex = ivHex;
    }
}

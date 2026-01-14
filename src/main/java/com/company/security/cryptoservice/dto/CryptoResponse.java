package com.company.security.cryptoservice.dto;

public class CryptoResponse {

    private String data;

    public CryptoResponse(String data) {
        this.data = data;
    }

    public String getData() {
        return data;
    }
}

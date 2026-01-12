package com.company.security.cryptoservice.controller;

import com.company.security.cryptoservice.dto.*;
import com.company.security.cryptoservice.service.CryptoService;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/crypto")
public class CryptoController {

    private final CryptoService cryptoService;

    public CryptoController(CryptoService cryptoService) {
        this.cryptoService = cryptoService;
    }

    @PostMapping("/encrypt")
    public CryptoResponse encrypt(@RequestBody EncryptRequest request) {
        return new CryptoResponse(
                cryptoService.encrypt(
                        request.getKeyAlias(),
                        request.getPlainText()
                )
        );
    }

    @PostMapping("/decrypt")
    public CryptoResponse decrypt(@RequestBody DecryptRequest request) {
        return new CryptoResponse(
                cryptoService.decrypt(
                        request.getKeyAlias(),
                        request.getEncryptedText()
                )
        );
    }
}

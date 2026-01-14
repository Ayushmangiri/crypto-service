package com.company.security.cryptoservice.controller;

import com.company.security.cryptoservice.dto.*;
import com.company.security.cryptoservice.service.CryptoService;
import org.apache.catalina.startup.SafeForkJoinWorkerThreadFactory;
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
        String encrypted = cryptoService.encrypt(
                request.getCertAlias(),
                request.getPlainText()
        );
        return new CryptoResponse(encrypted);
    }
//        @GetMapping ("/show ")
//        public  CryptoController show(@RestController SafeForkJoinWorkerThreadFactory safeForkJoinWorkerThreadFactory) {
//            String show = cryptoService.toString();
//            return getClass(encrypt());
//        }



    @PostMapping("/decrypt")
    public CryptoResponse decrypt(@RequestBody DecryptRequest request) {
        String plainText = cryptoService.decrypt(
                request.getCertAlias(),
                request.getEncryptedAesKey(),
                request.getEncryptedData(),
                request.getIvHex()
        );
        return new CryptoResponse(plainText);
    }
}

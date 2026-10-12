package com.moshood.ForYourEyesOnly.controller;

import java.io.IOException;

import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import com.moshood.ForYourEyesOnly.Dto.CryptoDto;
import com.moshood.ForYourEyesOnly.service.ImageDecryptorService;
import com.moshood.ForYourEyesOnly.service.ImageEncryptorService;

@Controller
@RequestMapping("/")
public class WelcomeController {

    private final ImageDecryptorService imageDecryptorService;
    private final ImageEncryptorService imageEncryptorService;

    public WelcomeController(ImageEncryptorService imageEncryptorService, ImageDecryptorService imageDecryptorService) {
        this.imageEncryptorService = imageEncryptorService;
        this.imageDecryptorService = imageDecryptorService;
    }

    @GetMapping
    public String getHomePage(Model model) {
        return "index";
    }

    @PostMapping("/encrypt")
    public ResponseEntity<byte[]> encryptImage(@ModelAttribute CryptoDto cryptoDto, Model model) throws IOException {
        resolvePassword(cryptoDto);
        byte[] encryptedImage = imageEncryptorService.encryptImage(cryptoDto)
                .orElseThrow(() -> new IllegalStateException("Failed to encrypt image: empty result"));

        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=secret.png")
                .contentType(MediaType.IMAGE_PNG)
                .body(encryptedImage);
    }

    @PostMapping("/decrypt")
    public ResponseEntity<byte[]> decryptImage(@ModelAttribute CryptoDto cryptoDto, Model model) throws IOException {
        resolvePassword(cryptoDto);
        byte[] decryptedImage = imageDecryptorService.decryptImage(cryptoDto)
                .orElseThrow(() -> new IllegalStateException("Failed to decrypt image: empty result"));

        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=secret.png")
                .contentType(MediaType.IMAGE_PNG)
                .body(decryptedImage);
    }

    private void resolvePassword(CryptoDto dto) {
        if (dto != null) {
            if (dto.getPassword() == null || dto.getPassword().trim().isEmpty()) {
                dto.setPassword(String.valueOf(dto.getKey()));
            }
        }
    }
}

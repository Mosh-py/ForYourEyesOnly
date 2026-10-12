package com.moshood.ForYourEyesOnly.service.mobileApp.controller;

import java.io.IOException;

import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestPart;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import com.moshood.ForYourEyesOnly.Dto.CryptoDto;
import com.moshood.ForYourEyesOnly.model.AppResponse;
import com.moshood.ForYourEyesOnly.service.ImageCompressorService;
import com.moshood.ForYourEyesOnly.service.ImageDecryptorService;
import com.moshood.ForYourEyesOnly.service.ImageEncryptorService;

@RestController
@RequestMapping("api/v1/app")
public class WelcomeAppController {

    private final ImageDecryptorService imageDecryptorService;
    private final ImageEncryptorService imageEncryptorService;
    private final ImageCompressorService imageCompressorService;

    public WelcomeAppController(ImageEncryptorService imageEncryptorService, ImageDecryptorService imageDecryptorService,
            ImageCompressorService imageCompressorService) {
        this.imageEncryptorService = imageEncryptorService;
        this.imageDecryptorService = imageDecryptorService;
        this.imageCompressorService = imageCompressorService;
    }

    @PostMapping("/encrypt")
    public ResponseEntity<byte[]> encryptImage(@RequestPart("data") CryptoDto cryptoDto) throws IOException {
        resolvePassword(cryptoDto);
        byte[] encryptedImage = imageEncryptorService.encryptImage(cryptoDto)
                .orElseThrow(() -> new IllegalStateException("Failed to encrypt image: empty result"));

        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=secret.png")
                .contentType(MediaType.IMAGE_PNG)
                .body(encryptedImage);
    }

    @PostMapping("/decrypt")
    public ResponseEntity<byte[]> decryptImage(@RequestPart("data") CryptoDto cryptoDto) throws IOException {
        resolvePassword(cryptoDto);
        byte[] decryptedImage = imageDecryptorService.decryptImage(cryptoDto)
                .orElseThrow(() -> new IllegalStateException("Failed to decrypt image: empty result"));

        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=secret.png")
                .contentType(MediaType.IMAGE_PNG)
                .body(decryptedImage);
    }

    @PostMapping("/compress")
    public ResponseEntity<AppResponse> compressImage(@RequestParam MultipartFile file) {
        if (file == null || file.isEmpty()) {
            return ResponseEntity.badRequest().body(new AppResponse(null, "Please input an image"));
        }
        AppResponse response = imageCompressorService.compressImage(file);
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=compressedImage.png")
                .contentType(MediaType.IMAGE_PNG)
                .body(response);
    }

    private void resolvePassword(CryptoDto dto) {
        if (dto != null) {
            if (dto.getPassword() == null || dto.getPassword().trim().isEmpty()) {
                dto.setPassword(String.valueOf(dto.getKey()));
            }
        }
    }
}

package com.moshood.ForYourEyesOnly.controller;

import java.awt.image.BufferedImage;
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
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;

import com.moshood.ForYourEyesOnly.Dto.CryptoDto;
import com.moshood.ForYourEyesOnly.service.ImageDecryptorService;
import com.moshood.ForYourEyesOnly.service.ImageEncryptorService;

@Controller
@RequestMapping("/")
public class WelcomeController {

    private final ImageDecryptorService imageDecryptorService;

	private final ImageEncryptorService imageEncryptorService;
	@GetMapping
	public String getHomePage(Model model) {
		return "index";
	}
	
	public WelcomeController(ImageEncryptorService imageEncryptorService, ImageDecryptorService imageDecryptorService) {
		this.imageEncryptorService = imageEncryptorService;
		this.imageDecryptorService = imageDecryptorService;
	}
	
	@PostMapping("/encrypt")
	public ResponseEntity<byte[]> encryptImage(@ModelAttribute CryptoDto cryptoDto, Model model) throws IOException {
		
		try {
			byte[] encryptedImage = imageEncryptorService.encryptImage(cryptoDto).get();
			
			return ResponseEntity.ok().header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=secret.png").contentType(MediaType.IMAGE_PNG).body(encryptedImage);
		} catch(Exception e) {
			return ResponseEntity.internalServerError().build();
		}
		
	
	}
	
	@PostMapping("/decrypt")
	public ResponseEntity<byte[]> decryptImage(@ModelAttribute CryptoDto cryptoDto, Model model){
		
		try {
			byte[] decryptedImage = imageDecryptorService.decryptImage(cryptoDto).get();
			
			return ResponseEntity.ok().header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=secret.png").contentType(MediaType.IMAGE_PNG).body(decryptedImage);
		} catch (Exception e) {
			return ResponseEntity.internalServerError().build();
		}
		
	}
}

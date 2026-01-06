package com.moshood.ForYourEyesOnly.service;

import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.util.Optional;
import java.util.Random;

import javax.imageio.ImageIO;

import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import com.moshood.ForYourEyesOnly.Dto.CryptoDto;
import com.moshood.ForYourEyesOnly.helper.ImageCryptoHelper;
import com.moshood.ForYourEyesOnly.helper.ImageEncryptor;
import com.moshood.ForYourEyesOnly.helper.ImageToByteHelper;
import com.moshood.ForYourEyesOnly.model.ImageBundle;

@Service
public class ImageEncryptorService {

	public Optional<byte[]> encryptImage(CryptoDto dto) throws IOException {
		
		
		MultipartFile file = dto.getFile();
		int key = dto.getKey();
		long seed = key + 234000;
		
		BufferedImage rawImage = encrypt(file, key, seed);
		byte[] byteArray = ImageToByteHelper.convertImageToByte(rawImage);
		return Optional.ofNullable(byteArray);
	}
	
	public BufferedImage encrypt(MultipartFile file, int key, long seed) throws IOException {
		Optional<BufferedImage> fileToImage = ImageCryptoHelper.convertFileToImage(file);
		ImageBundle bundleImage = ImageCryptoHelper.createNewImage(fileToImage); 
		
		BufferedImage image = diffuseImage(ImageCryptoHelper.confuseImage(bundleImage, key), seed);
		return image;
	}
	

	
	private BufferedImage diffuseImage(BufferedImage encrypted, long seed) throws IOException {
		
		
		Random rnd = new Random(seed);
		int width = encrypted.getWidth();
		int height = encrypted.getHeight();
		
		// compressing the image pixel into a 1d Array
		int[] compressedImageArray = encrypted.getRGB(0, 0, encrypted.getWidth(), encrypted.getHeight(), null, 0, width);
		int[] randomValues = ImageCryptoHelper.futureRandomToList(rnd, compressedImageArray.length);
		for (int i = compressedImageArray.length - 1, j = 0; i >= 0; i--, j++) {
			int value = randomValues[j] ;
			int temp = compressedImageArray[i];
			compressedImageArray[i] = compressedImageArray[value];
			compressedImageArray[value] = temp;
		}
		
		encrypted.setRGB(0, 0, width, height, compressedImageArray, 0, width);
		return encrypted;
		
		
	}
	
	
}

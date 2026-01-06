package com.moshood.ForYourEyesOnly.service;

import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;
import java.util.Optional;
import java.util.Random;

import javax.imageio.ImageIO;

import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import com.moshood.ForYourEyesOnly.Dto.CryptoDto;
import com.moshood.ForYourEyesOnly.helper.ImageCryptoHelper;
import com.moshood.ForYourEyesOnly.helper.ImageToByteHelper;
import com.moshood.ForYourEyesOnly.model.ImageBundle;

import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
public class ImageDecryptorService {

	
	public Optional<byte[]> decryptImage(CryptoDto dto) throws IOException {
		
		
		MultipartFile file = dto.getFile();
		int key = dto.getKey();
		long seed = key + 234000;
		
		BufferedImage rawImage = decrypt(file, key, seed).get();
		log.info("The size is " + (rawImage.getHeight() * rawImage.getWidth()) / (1024 * 1024));
		byte[] byteArray = ImageToByteHelper.convertImageToByte(rawImage);
		return Optional.ofNullable(byteArray);
	}
	
	public  Optional<BufferedImage> decrypt(MultipartFile file, int key, long seed) throws IOException {
		Optional<BufferedImage> fileToImage = ImageCryptoHelper.convertFileToImage(file);
		ImageBundle bundleImage = ImageCryptoHelper.createNewImage(fileToImage); 
		BufferedImage image =  diffuseImage(ImageCryptoHelper.confuseImage(bundleImage, key), seed);
		return Optional.ofNullable(image);
	}
	
	private BufferedImage diffuseImage(BufferedImage encrypted, long seed) throws IOException {
		
		
		Random rnd = new Random(seed);
		int width = encrypted.getWidth();
		int height = encrypted.getHeight();
		
		// compressing the image pixel into a 1d Array
		int[] compressedImageArray = encrypted.getRGB(0, 0, encrypted.getWidth(), encrypted.getHeight(), null, 0, width);
		System.out.println(compressedImageArray.length);
		int[] randomValues = ImageCryptoHelper.futureRandomToList(rnd, compressedImageArray.length); 
		System.out.println(randomValues.length);
		for (int i = 0, j = randomValues.length -1 ; i < compressedImageArray.length ; i++, j--) {
			int value = randomValues[j];
			int temp = compressedImageArray[i];
			compressedImageArray[i] = compressedImageArray[value];
			compressedImageArray[value] = temp;
		}
		
		encrypted.setRGB(0, 0, width, height, compressedImageArray, 0, width);
		return encrypted;
		
		
	}
}

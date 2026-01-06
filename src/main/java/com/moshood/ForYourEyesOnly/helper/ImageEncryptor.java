package com.moshood.ForYourEyesOnly.helper;

import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;
import java.util.Optional;
import java.util.Random;

import javax.imageio.IIOException;
import javax.imageio.ImageIO;

import org.springframework.web.multipart.MultipartFile;

import com.moshood.ForYourEyesOnly.model.ImageBundle;


public class ImageEncryptor {

	public static long counter = 0;
	private static String path = "/home/adageje-moshood/Pictures/encryptedFile/";
	private static String imageFile = "encry" + ++counter + ".png";
	
	private static File outputFile = new File(path+imageFile);
	
	public static void encrypt(File file, int key, long seed) throws IOException {
		Optional<BufferedImage> fileToImage = ImageCryptoHelper.convertFileToimage(file);
		ImageBundle bundleImage = ImageCryptoHelper.createNewImage(fileToImage); 
		diffuseImage(ImageCryptoHelper.confuseImage(bundleImage, key), seed);
	}
	
	public static void encrypt(MultipartFile file, int key, long seed) throws IOException {
		Optional<BufferedImage> fileToImage = ImageCryptoHelper.convertFileToImage(file);
		ImageBundle bundleImage = ImageCryptoHelper.createNewImage(fileToImage); 
		diffuseImage(ImageCryptoHelper.confuseImage(bundleImage, key), seed);
	}
	
	private static void diffuseImage(BufferedImage encrypted, long seed) throws IOException {
		
		
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
		ImageIO.write(encrypted, "png", outputFile);
		
		System.out.println(" Encrtyped ooooo");
		
		
	}
	
	
}

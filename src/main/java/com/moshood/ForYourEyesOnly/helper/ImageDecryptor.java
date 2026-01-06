package com.moshood.ForYourEyesOnly.helper;

import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Random;

import javax.imageio.IIOException;
import javax.imageio.ImageIO;

import com.moshood.ForYourEyesOnly.model.ImageBundle;



public class ImageDecryptor {

	public static long counter = 0;
	private static String path = "/home/adageje-moshood/Pictures/decryptedFile/";
	private static String imageFile = "decry" + ++counter + ".png";

	private static File outputFile = new File(path + imageFile);

	public static void decrypt(File file, int key, long seed) throws IOException {
		Optional<BufferedImage> fileToImage = ImageCryptoHelper.convertFileToimage(file);
		ImageBundle bundleImage = ImageCryptoHelper.createNewImage(fileToImage); 
		diffuseImage(ImageCryptoHelper.confuseImage(bundleImage, key), seed);
	}
	
	private static void diffuseImage(BufferedImage encrypted, long seed) throws IOException {
		
		
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
		ImageIO.write(encrypted, "png", outputFile);
		
		System.out.println(" deccytyped ooooo");
		
		
	}
	

	
}

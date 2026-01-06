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

import org.springframework.web.multipart.MultipartFile;

import com.moshood.ForYourEyesOnly.model.ImageBundle;

public class ImageCryptoHelper {
	
	public static Optional<BufferedImage> convertFileToImage(MultipartFile file) {
		BufferedImage image = null;
		Optional<BufferedImage> container = Optional.empty();

		try {
			image = ImageIO.read(file.getInputStream());
			container = Optional.of(image);
		} catch (IllegalArgumentException e) {
			e.printStackTrace();
			;
		} catch (IIOException E) {
			E.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}

		return container;
	}

	public static Optional<BufferedImage> convertFileToimage(File file) {

		BufferedImage image = null;
		Optional<BufferedImage> container = Optional.empty();

		try {
			image = ImageIO.read(file);
			container = Optional.of(image);
		} catch (IllegalArgumentException e) {
			e.printStackTrace();
			;
		} catch (IIOException E) {
			E.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}

		return container;
	}

	public static ImageBundle createNewImage(Optional<BufferedImage> container) {

		BufferedImage image = container.get();
		int width = image.getWidth();
		int height = image.getHeight();

		BufferedImage preImage = new BufferedImage(width, height, BufferedImage.TYPE_INT_RGB);
		ImageBundle bundle = new ImageBundle(image, preImage);
		return bundle;
	}

	public static BufferedImage confuseImage(ImageBundle image, int key) throws IOException {

		BufferedImage original = image.originalImage();
		BufferedImage encrypted = image.encryptedImage();

		for (int x = 0; x < encrypted.getWidth(); x++) {
			for (int y = 0; y < encrypted.getHeight(); y++) {
				int initialValue = original.getRGB(x, y);
				int confusion = initialValue ^ key;
				encrypted.setRGB(x, y, confusion);
			}
		}
		return encrypted;
	}

	public static int[] futureRandomToList(Random rnd, int noOfRepeat) {
		int[] randomNumbers = new int[noOfRepeat];
		for (int i = 0; i < noOfRepeat; i++) {
			int randomValues = rnd.nextInt(noOfRepeat);
			randomNumbers[i] = randomValues;
		}

		return randomNumbers;
	}
}

package com.moshood.ForYourEyesOnly.helper;

import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

import javax.imageio.ImageIO;

public class ImageToByteHelper {

	public static byte[] convertImageToByte(BufferedImage image) throws IOException {

		ByteArrayOutputStream arrayStream = new ByteArrayOutputStream();

		ImageIO.write(image, "png", arrayStream);
		return arrayStream.toByteArray();
	}
}

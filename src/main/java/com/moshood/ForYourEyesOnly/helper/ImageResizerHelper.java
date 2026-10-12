package com.moshood.ForYourEyesOnly.helper;

import java.awt.Graphics2D;
import java.awt.image.BufferedImage;
import java.util.Optional;

public class ImageResizerHelper {

	public static Optional<BufferedImage> resizeImage(Optional<BufferedImage> image ) {
		
		int limit = 1280;
		
		int height = image.get().getHeight();
		int width = image.get().getWidth();
		
		if (height <= limit && width <= limit)
			return image;
		
		int max = Math.max(height, width);
		double scale = (double) limit / max;
		
		int newWidth = Math.max(1, (int) Math.round(width * scale));
		int newHeight = Math.max(1, (int) Math.round(height * scale));
		
		BufferedImage newImage = new BufferedImage(newWidth, newHeight, BufferedImage.TYPE_INT_RGB);
		Graphics2D g = newImage.createGraphics();
		
		g.drawImage(image.get().getScaledInstance(newWidth, newHeight, java.awt.Image.SCALE_SMOOTH), 0, 0, null);
	    g.dispose();

	    return Optional.ofNullable(newImage);
	}
}

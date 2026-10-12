package com.moshood.ForYourEyesOnly.service;

import java.awt.image.BufferedImage;
import java.io.IOException;
import java.util.Optional;

import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import com.moshood.ForYourEyesOnly.helper.ImageCryptoHelper;
import com.moshood.ForYourEyesOnly.helper.ImageResizerHelper;
import com.moshood.ForYourEyesOnly.helper.ImageToByteHelper;
import com.moshood.ForYourEyesOnly.model.AppResponse;

@Service
public class ImageCompressorService {

	public AppResponse compressImage(MultipartFile file) {
		String message = " Something went wrong , please try again ";
		byte[] fileByte = null;
		try {
			fileByte = file.getBytes();
			if (!file.isEmpty()) {
				Optional<BufferedImage> image = ImageCryptoHelper.convertFileToImage(file);
				Optional<BufferedImage> resizedImage = ImageResizerHelper.resizeImage(image);
				message = "Compressed Successfully";
				AppResponse response = new AppResponse(ImageToByteHelper.convertImageToByte(resizedImage.get()), message );
				return response;
			}
		} catch (IOException e) {
			message = "Something went wrong, please try again";
			return new AppResponse(fileByte, message);
		}
		
		return new AppResponse(fileByte, message);
	}
}

package com.moshood.ForYourEyesOnly.service;

import java.awt.image.BufferedImage;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Optional;

import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import com.moshood.ForYourEyesOnly.Dto.CryptoDto;
import com.moshood.ForYourEyesOnly.crypto.VisualAeadEngine;
import com.moshood.ForYourEyesOnly.helper.ImageCryptoHelper;
import com.moshood.ForYourEyesOnly.helper.ImageResizerHelper;
import com.moshood.ForYourEyesOnly.helper.ImageToByteHelper;
import com.moshood.ForYourEyesOnly.helper.PngMetadataHelper;
import com.moshood.ForYourEyesOnly.model.ImageBundle;

import lombok.extern.slf4j.Slf4j;

/**
 * Service responsible for format-preserving visual image encryption using VisualAeadEngine
 * and injecting compliant PNG authentication metadata chunks.
 */
@Service
@Slf4j
public class ImageEncryptorService {

    public static final String METADATA_KEYWORD = "fyeO";

    /**
     * Encrypts the image supplied in CryptoDto, injects the fyeO authentication chunk,
     * and returns the resulting PNG bytes.
     */
    public Optional<byte[]> encryptImage(CryptoDto dto) throws IOException {
        if (dto == null || dto.getFile() == null || dto.getFile().isEmpty()) {
            throw new IllegalArgumentException("Input file must not be null or empty");
        }

        String password = resolvePassword(dto);
        MultipartFile file = dto.getFile();

        Optional<BufferedImage> fileToImage = ImageCryptoHelper.convertFileToImage(file);
        if (fileToImage.isEmpty()) {
            throw new IllegalArgumentException("Invalid or unsupported image file");
        }

        Optional<BufferedImage> resizedImage = ImageResizerHelper.resizeImage(fileToImage);
        BufferedImage sourceImage = resizedImage.orElse(fileToImage.get());

        byte[] finalPngBytes = encryptImageBytes(sourceImage, password);
        return Optional.ofNullable(finalPngBytes);
    }

    /**
     * Core encryption routine: Encrypts BufferedImage with VisualAeadEngine, converts to PNG bytes,
     * and injects the fyeO metadata chunk.
     */
    public byte[] encryptImageBytes(BufferedImage sourceImage, String password) throws IOException {
        if (sourceImage == null) {
            throw new IllegalArgumentException("Source image must not be null");
        }
        try {
            char[] passwordChars = password != null ? password.toCharArray() : new char[0];
            VisualAeadEngine.EncryptedPackage encryptedPackage =
                    VisualAeadEngine.encrypt(sourceImage, passwordChars);

            byte[] cipherPngBytes = ImageToByteHelper.convertImageToByte(encryptedPackage.cipherImage());
            return PngMetadataHelper.injectTextChunk(cipherPngBytes, METADATA_KEYWORD, encryptedPackage.metadataBase64());
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Cryptographic encryption failed", e);
        }
    }

    private String resolvePassword(CryptoDto dto) {
        if (dto.getPassword() != null && !dto.getPassword().trim().isEmpty()) {
            return dto.getPassword();
        }
        return String.valueOf(dto.getKey());
    }

    @Deprecated(forRemoval = true)
    public BufferedImage encrypt(MultipartFile file, int key, long seed) throws IOException {
        Optional<BufferedImage> fileToImage = ImageCryptoHelper.convertFileToImage(file);
        Optional<BufferedImage> resizedImage = ImageResizerHelper.resizeImage(fileToImage);
        ImageBundle bundleImage = ImageCryptoHelper.createNewImage(resizedImage); 
        return diffuseImage(ImageCryptoHelper.confuseImage(bundleImage, key), seed);
    }

    @Deprecated(forRemoval = true)
    private BufferedImage diffuseImage(BufferedImage encrypted, long seed) throws IOException {
        java.util.Random rnd = new java.util.Random(seed);
        int width = encrypted.getWidth();
        int height = encrypted.getHeight();
        int[] compressedImageArray = encrypted.getRGB(0, 0, width, height, null, 0, width);
        int[] randomValues = ImageCryptoHelper.futureRandomToList(rnd, compressedImageArray.length);
        for (int i = compressedImageArray.length - 1, j = 0; i >= 0; i--, j++) {
            int value = randomValues[j];
            int temp = compressedImageArray[i];
            compressedImageArray[i] = compressedImageArray[value];
            compressedImageArray[value] = temp;
        }
        encrypted.setRGB(0, 0, width, height, compressedImageArray, 0, width);
        return encrypted;
    }
}

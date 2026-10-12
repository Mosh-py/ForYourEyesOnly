package com.moshood.ForYourEyesOnly.service;

import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.util.Optional;

import javax.imageio.ImageIO;

import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import com.moshood.ForYourEyesOnly.Dto.CryptoDto;
import com.moshood.ForYourEyesOnly.crypto.VisualAeadEngine;
import com.moshood.ForYourEyesOnly.exception.AuthenticationFailedException;
import com.moshood.ForYourEyesOnly.exception.CorruptedImageException;
import com.moshood.ForYourEyesOnly.helper.ImageCryptoHelper;
import com.moshood.ForYourEyesOnly.helper.ImageToByteHelper;
import com.moshood.ForYourEyesOnly.helper.PngMetadataHelper;
import com.moshood.ForYourEyesOnly.model.ImageBundle;

import lombok.extern.slf4j.Slf4j;

/**
 * Service responsible for format-preserving visual image decryption,
 * extracting and validating PNG metadata authentication chunks, and verifying HMAC tags in constant time.
 */
@Service
@Slf4j
public class ImageDecryptorService {

    public static final String METADATA_KEYWORD = "fyeO";
    public static final String CORRUPTED_ERROR_MSG =
            "CORRUPTED_OR_COMPRESSED_IMAGE: Missing or invalid authentication metadata. Ensure the image was sent as an uncompressed document.";
    public static final String AUTH_FAILED_ERROR_MSG =
            "AUTHENTICATION_FAILED: Incorrect password or image pixels have been altered.";

    /**
     * Decrypts the encrypted PNG provided in CryptoDto.
     * Extracts and validates fyeO metadata chunk, decrypts via VisualAeadEngine,
     * and returns the restored original PNG bytes.
     */
    public Optional<byte[]> decryptImage(CryptoDto dto) throws IOException {
        if (dto == null || dto.getFile() == null || dto.getFile().isEmpty()) {
            throw new IllegalArgumentException("Input file must not be null or empty");
        }

        String password = resolvePassword(dto);
        byte[] pngBytes = dto.getFile().getBytes();

        byte[] decryptedBytes = decryptImageBytes(pngBytes, password);
        return Optional.ofNullable(decryptedBytes);
    }

    /**
     * Core decryption routine: Extracts fyeO metadata chunk, validates CRC and presence,
     * decrypts with VisualAeadEngine, and returns plain PNG bytes.
     */
    public byte[] decryptImageBytes(byte[] pngBytes, String password) throws IOException {
        if (pngBytes == null || pngBytes.length == 0) {
            throw new IllegalArgumentException("Input PNG bytes must not be null or empty");
        }

        // 1. Extract fyeO metadata chunk
        String metadataBase64;
        try {
            Optional<String> chunkOpt = PngMetadataHelper.extractTextChunk(pngBytes, METADATA_KEYWORD);
            if (chunkOpt.isEmpty()) {
                throw new CorruptedImageException(CORRUPTED_ERROR_MSG);
            }
            metadataBase64 = chunkOpt.get();
        } catch (CorruptedImageException e) {
            throw new CorruptedImageException(CORRUPTED_ERROR_MSG, e);
        }

        // 2. Decode cipher image
        BufferedImage cipherImage;
        try (InputStream is = new ByteArrayInputStream(pngBytes)) {
            cipherImage = ImageIO.read(is);
        }
        if (cipherImage == null) {
            throw new CorruptedImageException(CORRUPTED_ERROR_MSG);
        }

        // 3. Decrypt with VisualAeadEngine
        BufferedImage plainImage;
        try {
            char[] passwordChars = password != null ? password.toCharArray() : new char[0];
            plainImage = VisualAeadEngine.decrypt(cipherImage, metadataBase64, passwordChars);
        } catch (SecurityException | GeneralSecurityException e) {
            throw new AuthenticationFailedException(AUTH_FAILED_ERROR_MSG, e);
        }

        // 4. Convert plain image to PNG bytes
        return ImageToByteHelper.convertImageToByte(plainImage);
    }

    private String resolvePassword(CryptoDto dto) {
        if (dto.getPassword() != null && !dto.getPassword().trim().isEmpty()) {
            return dto.getPassword();
        }
        return String.valueOf(dto.getKey());
    }

    @Deprecated(forRemoval = true)
    public Optional<BufferedImage> decrypt(MultipartFile file, int key, long seed) throws IOException {
        Optional<BufferedImage> fileToImage = ImageCryptoHelper.convertFileToImage(file);
        ImageBundle bundleImage = ImageCryptoHelper.createNewImage(fileToImage); 
        BufferedImage image = diffuseImage(ImageCryptoHelper.confuseImage(bundleImage, key), seed);
        return Optional.ofNullable(image);
    }

    @Deprecated(forRemoval = true)
    private BufferedImage diffuseImage(BufferedImage encrypted, long seed) throws IOException {
        java.util.Random rnd = new java.util.Random(seed);
        int width = encrypted.getWidth();
        int height = encrypted.getHeight();
        int[] compressedImageArray = encrypted.getRGB(0, 0, width, height, null, 0, width);
        int[] randomValues = ImageCryptoHelper.futureRandomToList(rnd, compressedImageArray.length); 
        for (int i = 0, j = randomValues.length - 1; i < compressedImageArray.length; i++, j--) {
            int value = randomValues[j];
            int temp = compressedImageArray[i];
            compressedImageArray[i] = compressedImageArray[value];
            compressedImageArray[value] = temp;
        }
        encrypted.setRGB(0, 0, width, height, compressedImageArray, 0, width);
        return encrypted;
    }
}

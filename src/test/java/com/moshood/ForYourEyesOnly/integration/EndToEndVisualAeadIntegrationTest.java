package com.moshood.ForYourEyesOnly.integration;

import com.moshood.ForYourEyesOnly.Dto.CryptoDto;
import com.moshood.ForYourEyesOnly.crypto.VisualAeadEngine;
import com.moshood.ForYourEyesOnly.exception.AuthenticationFailedException;
import com.moshood.ForYourEyesOnly.exception.CorruptedImageException;
import com.moshood.ForYourEyesOnly.helper.ImageToByteHelper;
import com.moshood.ForYourEyesOnly.helper.PngMetadataHelper;
import com.moshood.ForYourEyesOnly.service.ImageDecryptorService;
import com.moshood.ForYourEyesOnly.service.ImageEncryptorService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.web.servlet.MockMvc;

import javax.imageio.ImageIO;
import java.awt.Color;
import java.awt.Graphics2D;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Optional;

import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class EndToEndVisualAeadIntegrationTest {

    @Autowired
    private ImageEncryptorService encryptorService;

    @Autowired
    private ImageDecryptorService decryptorService;

    @Autowired
    private MockMvc mockMvc;

    private BufferedImage testImage;
    private byte[] testImagePngBytes;

    @BeforeEach
    void setUp() throws IOException {
        int width = 32;
        int height = 32;
        testImage = new BufferedImage(width, height, BufferedImage.TYPE_INT_RGB);
        Graphics2D g = testImage.createGraphics();
        g.setColor(new Color(30, 80, 160));
        g.fillRect(0, 0, width, height);
        g.setColor(Color.YELLOW);
        g.fillRect(8, 8, 16, 16);
        g.setColor(Color.RED);
        g.drawString("FYEO", 2, 20);
        g.dispose();

        testImagePngBytes = ImageToByteHelper.convertImageToByte(testImage);
    }

    @Test
    @DisplayName("Full round-trip encryption, metadata injection, extraction, and decryption preserves exact pixels")
    void testFullRoundTripEncryptionAndDecryption() throws IOException {
        String password = "TopSecretPassword2026!";

        // 1. Encrypt
        MockMultipartFile inputFile = new MockMultipartFile(
                "file", "original.png", MediaType.IMAGE_PNG_VALUE, testImagePngBytes
        );
        CryptoDto encryptDto = new CryptoDto();
        encryptDto.setFile(inputFile);
        encryptDto.setPassword(password);

        Optional<byte[]> encryptedOpt = encryptorService.encryptImage(encryptDto);
        assertTrue(encryptedOpt.isPresent());
        byte[] encryptedPngBytes = encryptedOpt.get();

        // Verify valid PNG and metadata present
        assertTrue(PngMetadataHelper.hasPngSignature(encryptedPngBytes));
        Optional<String> metadataOpt = PngMetadataHelper.extractTextChunk(encryptedPngBytes, "fyeO");
        assertTrue(metadataOpt.isPresent(), "Metadata chunk 'fyeO' must be present in encrypted image");

        // Verify envelope is exactly 73 bytes decoded
        VisualAeadEngine.MetadataEnvelope envelope = VisualAeadEngine.MetadataEnvelope.fromBase64(metadataOpt.get());
        assertEquals(32, envelope.width());
        assertEquals(32, envelope.height());

        // 2. Decrypt
        MockMultipartFile cipherFile = new MockMultipartFile(
                "file", "secret.png", MediaType.IMAGE_PNG_VALUE, encryptedPngBytes
        );
        CryptoDto decryptDto = new CryptoDto();
        decryptDto.setFile(cipherFile);
        decryptDto.setPassword(password);

        Optional<byte[]> decryptedOpt = decryptorService.decryptImage(decryptDto);
        assertTrue(decryptedOpt.isPresent());
        byte[] decryptedPngBytes = decryptedOpt.get();

        BufferedImage restoredImage = ImageIO.read(new ByteArrayInputStream(decryptedPngBytes));
        assertNotNull(restoredImage);
        assertEquals(testImage.getWidth(), restoredImage.getWidth());
        assertEquals(testImage.getHeight(), restoredImage.getHeight());

        // Verify bit-for-bit parity on every pixel
        for (int y = 0; y < testImage.getHeight(); y++) {
            for (int x = 0; x < testImage.getWidth(); x++) {
                assertEquals(testImage.getRGB(x, y) & 0x00FFFFFF, restoredImage.getRGB(x, y) & 0x00FFFFFF,
                        "Mismatch at (" + x + "," + y + ")");
            }
        }
    }

    @Test
    @DisplayName("Backward compatibility: works with legacy numeric key when password is empty or null")
    void testLegacyKeyBackwardCompatibility() throws IOException {
        int legacyKey = 987654321;

        MockMultipartFile inputFile = new MockMultipartFile(
                "file", "original.png", MediaType.IMAGE_PNG_VALUE, testImagePngBytes
        );
        CryptoDto encryptDto = new CryptoDto();
        encryptDto.setFile(inputFile);
        encryptDto.setKey(legacyKey);
        encryptDto.setPassword(null);

        byte[] encryptedPng = encryptorService.encryptImage(encryptDto).orElseThrow();

        // Decrypt with matching key
        MockMultipartFile cipherFile = new MockMultipartFile(
                "file", "cipher.png", MediaType.IMAGE_PNG_VALUE, encryptedPng
        );
        CryptoDto decryptDto = new CryptoDto();
        decryptDto.setFile(cipherFile);
        decryptDto.setKey(legacyKey);

        byte[] decryptedPng = decryptorService.decryptImage(decryptDto).orElseThrow();
        BufferedImage restoredImage = ImageIO.read(new ByteArrayInputStream(decryptedPng));

        assertEquals(testImage.getRGB(10, 10) & 0x00FFFFFF, restoredImage.getRGB(10, 10) & 0x00FFFFFF);

        // Decrypt with wrong numeric key fails
        CryptoDto wrongKeyDto = new CryptoDto();
        wrongKeyDto.setFile(cipherFile);
        wrongKeyDto.setKey(111111);

        assertThrows(AuthenticationFailedException.class, () -> decryptorService.decryptImage(wrongKeyDto));
    }

    @Test
    @DisplayName("Decryption rejects incorrect password with AuthenticationFailedException")
    void testWrongPasswordRejection() throws IOException {
        MockMultipartFile inputFile = new MockMultipartFile(
                "file", "original.png", MediaType.IMAGE_PNG_VALUE, testImagePngBytes
        );
        CryptoDto encryptDto = new CryptoDto();
        encryptDto.setFile(inputFile);
        encryptDto.setPassword("CorrectPassword123");

        byte[] encryptedPng = encryptorService.encryptImage(encryptDto).orElseThrow();

        MockMultipartFile cipherFile = new MockMultipartFile(
                "file", "cipher.png", MediaType.IMAGE_PNG_VALUE, encryptedPng
        );
        CryptoDto decryptDto = new CryptoDto();
        decryptDto.setFile(cipherFile);
        decryptDto.setPassword("IncorrectPassword999");

        AuthenticationFailedException ex = assertThrows(AuthenticationFailedException.class, () ->
                decryptorService.decryptImage(decryptDto));

        assertTrue(ex.getMessage().contains("AUTHENTICATION_FAILED"));
    }

    @Test
    @DisplayName("Decryption rejects pixel tampering with AuthenticationFailedException")
    void testPixelTamperRejection() throws IOException {
        String password = "StrongPassword456";
        MockMultipartFile inputFile = new MockMultipartFile(
                "file", "original.png", MediaType.IMAGE_PNG_VALUE, testImagePngBytes
        );
        CryptoDto encryptDto = new CryptoDto();
        encryptDto.setFile(inputFile);
        encryptDto.setPassword(password);

        byte[] encryptedPng = encryptorService.encryptImage(encryptDto).orElseThrow();

        // Tamper with a pixel in the cipher image while keeping the metadata intact
        BufferedImage cipherImage = ImageIO.read(new ByteArrayInputStream(encryptedPng));
        cipherImage.setRGB(0, 0, cipherImage.getRGB(0, 0) ^ 0x00FFFFFF);

        byte[] tamperedRawPng = ImageToByteHelper.convertImageToByte(cipherImage);
        String metadataBase64 = PngMetadataHelper.extractTextChunk(encryptedPng, "fyeO").orElseThrow();
        byte[] tamperedPngWithMeta = PngMetadataHelper.injectTextChunk(tamperedRawPng, "fyeO", metadataBase64);

        MockMultipartFile tamperedFile = new MockMultipartFile(
                "file", "tampered.png", MediaType.IMAGE_PNG_VALUE, tamperedPngWithMeta
        );
        CryptoDto decryptDto = new CryptoDto();
        decryptDto.setFile(tamperedFile);
        decryptDto.setPassword(password);

        AuthenticationFailedException ex = assertThrows(AuthenticationFailedException.class, () ->
                decryptorService.decryptImage(decryptDto));

        assertTrue(ex.getMessage().contains("AUTHENTICATION_FAILED"));
    }

    @Test
    @DisplayName("Decryption rejects images missing metadata with CorruptedImageException")
    void testMissingMetadataRejection() {
        MockMultipartFile unencryptedFile = new MockMultipartFile(
                "file", "plain.png", MediaType.IMAGE_PNG_VALUE, testImagePngBytes
        );
        CryptoDto decryptDto = new CryptoDto();
        decryptDto.setFile(unencryptedFile);
        decryptDto.setPassword("AnyPassword");

        CorruptedImageException ex = assertThrows(CorruptedImageException.class, () ->
                decryptorService.decryptImage(decryptDto));

        assertTrue(ex.getMessage().contains("CORRUPTED_OR_COMPRESSED_IMAGE"));
    }

    @Test
    @DisplayName("Decryption rejects images with invalid CRC on metadata with CorruptedImageException")
    void testCorruptedMetadataCrcRejection() throws IOException {
        String password = "ValidPassword789";
        MockMultipartFile inputFile = new MockMultipartFile(
                "file", "original.png", MediaType.IMAGE_PNG_VALUE, testImagePngBytes
        );
        CryptoDto encryptDto = new CryptoDto();
        encryptDto.setFile(inputFile);
        encryptDto.setPassword(password);

        byte[] encryptedPng = encryptorService.encryptImage(encryptDto).orElseThrow();

        // Corrupt the CRC of the fyeO chunk
        byte[] corruptedPng = encryptedPng.clone();
        int offset = 8;
        while (offset + 12 <= corruptedPng.length) {
            int length = ByteBuffer.wrap(corruptedPng, offset, 4).getInt();
            String chunkType = new String(corruptedPng, offset + 4, 4, StandardCharsets.US_ASCII);
            if ("tEXt".equals(chunkType)) {
                int crcOffset = offset + 8 + length;
                corruptedPng[crcOffset] ^= 0xFF; // corrupt CRC byte
                break;
            }
            offset += 12 + length;
        }

        MockMultipartFile corruptedFile = new MockMultipartFile(
                "file", "corrupted.png", MediaType.IMAGE_PNG_VALUE, corruptedPng
        );
        CryptoDto decryptDto = new CryptoDto();
        decryptDto.setFile(corruptedFile);
        decryptDto.setPassword(password);

        CorruptedImageException ex = assertThrows(CorruptedImageException.class, () ->
                decryptorService.decryptImage(decryptDto));

        assertTrue(ex.getMessage().contains("CORRUPTED_OR_COMPRESSED_IMAGE"));
    }

    @Test
    @DisplayName("MVC Endpoints: Encrypt and Decrypt return HTTP 200 on success")
    void testMvcEncryptAndDecryptSuccess() throws Exception {
        String password = "EndpointPassword123";
        MockMultipartFile multipartFile = new MockMultipartFile(
                "file", "test.png", MediaType.IMAGE_PNG_VALUE, testImagePngBytes
        );

        // POST /encrypt
        byte[] encryptedPngResponse = mockMvc.perform(multipart("/encrypt")
                        .file(multipartFile)
                        .param("password", password))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.IMAGE_PNG))
                .andReturn()
                .getResponse()
                .getContentAsByteArray();

        assertTrue(encryptedPngResponse.length > 0);
        assertTrue(PngMetadataHelper.hasPngSignature(encryptedPngResponse));

        // POST /decrypt with correct password
        MockMultipartFile cipherFile = new MockMultipartFile(
                "file", "encrypted.png", MediaType.IMAGE_PNG_VALUE, encryptedPngResponse
        );

        byte[] decryptedPngResponse = mockMvc.perform(multipart("/decrypt")
                        .file(cipherFile)
                        .param("password", password))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.IMAGE_PNG))
                .andReturn()
                .getResponse()
                .getContentAsByteArray();

        assertTrue(decryptedPngResponse.length > 0);
        BufferedImage restored = ImageIO.read(new ByteArrayInputStream(decryptedPngResponse));
        assertNotNull(restored);
        assertEquals(32, restored.getWidth());
    }

    @Test
    @DisplayName("MVC Endpoints: Wrong password returns HTTP 400 Bad Request with distinct diagnostic")
    void testMvcWrongPasswordReturnsHttp400() throws Exception {
        String password = "CorrectKey123";
        MockMultipartFile multipartFile = new MockMultipartFile(
                "file", "test.png", MediaType.IMAGE_PNG_VALUE, testImagePngBytes
        );

        byte[] encryptedPngResponse = mockMvc.perform(multipart("/encrypt")
                        .file(multipartFile)
                        .param("password", password))
                .andExpect(status().isOk())
                .andReturn()
                .getResponse()
                .getContentAsByteArray();

        MockMultipartFile cipherFile = new MockMultipartFile(
                "file", "encrypted.png", MediaType.IMAGE_PNG_VALUE, encryptedPngResponse
        );

        // POST /decrypt with wrong password -> HTTP 400
        mockMvc.perform(multipart("/decrypt")
                        .file(cipherFile)
                        .param("password", "WrongKey456"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.message", containsString("AUTHENTICATION_FAILED")));
    }

    @Test
    @DisplayName("MVC Endpoints: Missing metadata / compressed image returns HTTP 422 Unprocessable Entity")
    void testMvcMissingMetadataReturnsHttp422() throws Exception {
        MockMultipartFile plainPngFile = new MockMultipartFile(
                "file", "plain.png", MediaType.IMAGE_PNG_VALUE, testImagePngBytes
        );

        // POST /decrypt on plain unencrypted PNG -> HTTP 422
        mockMvc.perform(multipart("/decrypt")
                        .file(plainPngFile)
                        .param("password", "AnyKey"))
                .andExpect(status().isUnprocessableEntity())
                .andExpect(jsonPath("$.status").value(422))
                .andExpect(jsonPath("$.message", containsString("CORRUPTED_OR_COMPRESSED_IMAGE")));
    }
}

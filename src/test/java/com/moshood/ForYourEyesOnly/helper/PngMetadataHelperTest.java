package com.moshood.ForYourEyesOnly.helper;

import com.moshood.ForYourEyesOnly.crypto.VisualAeadEngine;
import com.moshood.ForYourEyesOnly.exception.CorruptedImageException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.imageio.ImageIO;
import java.awt.Color;
import java.awt.Graphics2D;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class PngMetadataHelperTest {

    private byte[] validPngBytes;

    @BeforeEach
    void setUp() throws IOException {
        BufferedImage image = new BufferedImage(16, 16, BufferedImage.TYPE_INT_RGB);
        Graphics2D g = image.createGraphics();
        g.setColor(Color.BLUE);
        g.fillRect(0, 0, 16, 16);
        g.dispose();

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ImageIO.write(image, "png", baos);
        validPngBytes = baos.toByteArray();
    }

    @Test
    @DisplayName("Successfully injects and extracts tEXt chunk with valid CRC32")
    void testInjectAndExtractTextChunk() {
        String keyword = "fyeO";
        String payload = "SampleEncryptedMetadataPayload12345";

        byte[] modifiedPng = PngMetadataHelper.injectTextChunk(validPngBytes, keyword, payload);

        assertNotNull(modifiedPng);
        assertTrue(modifiedPng.length > validPngBytes.length);
        assertTrue(PngMetadataHelper.hasPngSignature(modifiedPng));

        Optional<String> extracted = PngMetadataHelper.extractTextChunk(modifiedPng, keyword);
        assertTrue(extracted.isPresent());
        assertEquals(payload, extracted.get());
        assertEquals(payload, PngMetadataHelper.extractTextChunkOrNull(modifiedPng, keyword));

        // Missing keyword returns empty Optional
        Optional<String> missing = PngMetadataHelper.extractTextChunk(modifiedPng, "nonExistent");
        assertTrue(missing.isEmpty());
    }

    @Test
    @DisplayName("Round-trip injection and extraction of 73-byte binary envelope")
    void test73ByteEnvelopeRoundTripInPng() {
        byte[] salt = new byte[16];
        byte[] nonce = new byte[12];
        byte[] tag = new byte[32];
        for (int i = 0; i < 16; i++) salt[i] = (byte) (i + 1);
        for (int i = 0; i < 12; i++) nonce[i] = (byte) (i + 17);
        for (int i = 0; i < 32; i++) tag[i] = (byte) (i + 29);

        VisualAeadEngine.MetadataEnvelope envelope = new VisualAeadEngine.MetadataEnvelope(
                new byte[]{'F', 'Y', 'E', 'O'},
                (byte) 0x02,
                salt,
                nonce,
                1920,
                1080,
                tag
        );

        byte[] binaryEnvelope = envelope.toByteArray();
        assertEquals(73, binaryEnvelope.length, "Binary envelope must be exactly 73 bytes");

        String base64Payload = envelope.toBase64();
        byte[] pngWithMetadata = PngMetadataHelper.injectTextChunk(validPngBytes, "fyeO", base64Payload);

        Optional<String> extractedBase64 = PngMetadataHelper.extractTextChunk(pngWithMetadata, "fyeO");
        assertTrue(extractedBase64.isPresent());
        assertEquals(base64Payload, extractedBase64.get());

        VisualAeadEngine.MetadataEnvelope decodedEnvelope = VisualAeadEngine.MetadataEnvelope.fromBase64(extractedBase64.get());
        assertArrayEquals(envelope.magic(), decodedEnvelope.magic());
        assertEquals(envelope.version(), decodedEnvelope.version());
        assertArrayEquals(envelope.salt(), decodedEnvelope.salt());
        assertArrayEquals(envelope.nonce(), decodedEnvelope.nonce());
        assertEquals(envelope.width(), decodedEnvelope.width());
        assertEquals(envelope.height(), decodedEnvelope.height());
        assertArrayEquals(envelope.hmacTag(), decodedEnvelope.hmacTag());
    }

    @Test
    @DisplayName("Detects invalid PNG signatures and malformed buffers")
    void testInvalidPngDetection() {
        assertFalse(PngMetadataHelper.hasPngSignature(null));
        assertFalse(PngMetadataHelper.hasPngSignature(new byte[0]));
        assertFalse(PngMetadataHelper.hasPngSignature(new byte[]{1, 2, 3, 4}));
        assertFalse(PngMetadataHelper.hasPngSignature("NOT_A_PNG_FILE!!".getBytes(StandardCharsets.US_ASCII)));

        assertTrue(PngMetadataHelper.isValidPng(validPngBytes));

        // Injecting into non-PNG bytes throws IllegalArgumentException
        assertThrows(IllegalArgumentException.class, () ->
                PngMetadataHelper.injectTextChunk(null, "fyeO", "data"));
        assertThrows(IllegalArgumentException.class, () ->
                PngMetadataHelper.injectTextChunk(new byte[]{1, 2, 3}, "fyeO", "data"));
        assertThrows(IllegalArgumentException.class, () ->
                PngMetadataHelper.injectTextChunk("JUST_RANDOM_TEXT_DATA".getBytes(StandardCharsets.UTF_8), "fyeO", "data"));

        // Invalid keyword validation
        assertThrows(IllegalArgumentException.class, () ->
                PngMetadataHelper.injectTextChunk(validPngBytes, null, "data"));
        assertThrows(IllegalArgumentException.class, () ->
                PngMetadataHelper.injectTextChunk(validPngBytes, "", "data"));
        assertThrows(IllegalArgumentException.class, () ->
                PngMetadataHelper.injectTextChunk(validPngBytes, "a".repeat(80), "data"));

        // Null payload validation
        assertThrows(IllegalArgumentException.class, () ->
                PngMetadataHelper.injectTextChunk(validPngBytes, "fyeO", null));

        // Extracting from non-PNG bytes returns empty Optional
        assertTrue(PngMetadataHelper.extractTextChunk(null, "fyeO").isEmpty());
        assertTrue(PngMetadataHelper.extractTextChunk(new byte[]{0, 1, 2}, "fyeO").isEmpty());
        assertTrue(PngMetadataHelper.extractTextChunk("NON_PNG".getBytes(StandardCharsets.UTF_8), "fyeO").isEmpty());
    }

    @Test
    @DisplayName("Throws CorruptedImageException when CRC32 checksum mismatch is detected")
    void testCrcMismatchDetection() {
        String keyword = "fyeO";
        String payload = "IntegrityProtectedPayload";

        byte[] modifiedPng = PngMetadataHelper.injectTextChunk(validPngBytes, keyword, payload);

        // Find the tEXt chunk in the PNG byte array
        int offset = 8;
        int chunkDataOffset = -1;
        int chunkLength = -1;

        while (offset + 12 <= modifiedPng.length) {
            int length = ByteBuffer.wrap(modifiedPng, offset, 4).getInt();
            String chunkType = new String(modifiedPng, offset + 4, 4, StandardCharsets.US_ASCII);
            if ("tEXt".equals(chunkType)) {
                chunkDataOffset = offset + 8;
                chunkLength = length;
                break;
            }
            offset += 12 + length;
        }

        assertTrue(chunkDataOffset > 0, "tEXt chunk should be found");

        // Tamper with payload data byte without updating the CRC32 checksum
        byte[] tamperedPng = modifiedPng.clone();
        tamperedPng[chunkDataOffset + keyword.length() + 2] ^= 0x01; // flip bit in text data

        CorruptedImageException ex = assertThrows(CorruptedImageException.class, () ->
                PngMetadataHelper.extractTextChunk(tamperedPng, keyword));

        assertTrue(ex.getMessage().contains("CRC32 checksum mismatch"));
    }

    @Test
    @DisplayName("Throws IllegalArgumentException when PNG lacks IEND chunk during injection")
    void testMissingIendChunkThrowsException() {
        // Truncate valid PNG before IEND
        byte[] truncatedPng = new byte[validPngBytes.length - 12];
        System.arraycopy(validPngBytes, 0, truncatedPng, 0, truncatedPng.length);

        assertThrows(IllegalArgumentException.class, () ->
                PngMetadataHelper.injectTextChunk(truncatedPng, "fyeO", "payload"));
    }
}

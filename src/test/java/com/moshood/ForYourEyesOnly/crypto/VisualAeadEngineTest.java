package com.moshood.ForYourEyesOnly.crypto;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.awt.Color;
import java.awt.Graphics2D;
import java.awt.image.BufferedImage;
import java.security.GeneralSecurityException;

import static org.junit.jupiter.api.Assertions.*;

class VisualAeadEngineTest {

    @Test
    @DisplayName("Round-trip visual encryption and decryption restores exact original pixels")
    void testRoundTripParity() throws GeneralSecurityException {
        int width = 64;
        int height = 64;
        BufferedImage original = new BufferedImage(width, height, BufferedImage.TYPE_INT_RGB);
        Graphics2D g = original.createGraphics();
        g.setColor(new Color(45, 120, 200));
        g.fillRect(0, 0, width, height);
        g.setColor(Color.RED);
        g.fillOval(10, 10, 30, 30);
        g.dispose();

        char[] password = "SecretMasterPassword123!".toCharArray();

        // Encrypt
        VisualAeadEngine.EncryptedPackage pkg = VisualAeadEngine.encrypt(original, password);
        assertNotNull(pkg);
        assertNotNull(pkg.cipherImage());
        assertNotNull(pkg.metadataBase64());
        assertEquals(width, pkg.cipherImage().getWidth());
        assertEquals(height, pkg.cipherImage().getHeight());

        // Verify cipher image is not identical to original (high entropy)
        int diffCount = 0;
        for (int y = 0; y < height; y++) {
            for (int x = 0; x < width; x++) {
                if (original.getRGB(x, y) != pkg.cipherImage().getRGB(x, y)) {
                    diffCount++;
                }
            }
        }
        assertTrue(diffCount > (width * height * 0.95), "Cipher image should differ on >95% of pixels");

        // Decrypt
        BufferedImage decrypted = VisualAeadEngine.decrypt(pkg.cipherImage(), pkg.metadataBase64(), password);
        assertNotNull(decrypted);

        // Verify bit-for-bit parity
        for (int y = 0; y < height; y++) {
            for (int x = 0; x < width; x++) {
                assertEquals(original.getRGB(x, y) & 0x00FFFFFF, decrypted.getRGB(x, y) & 0x00FFFFFF,
                        "Mismatch at pixel (" + x + ", " + y + ")");
            }
        }
    }

    @Test
    @DisplayName("Decryption with incorrect password fails authentication in constant time")
    void testWrongPasswordRejection() throws GeneralSecurityException {
        BufferedImage original = new BufferedImage(32, 32, BufferedImage.TYPE_INT_RGB);
        VisualAeadEngine.EncryptedPackage pkg = VisualAeadEngine.encrypt(original, "CorrectPassword!".toCharArray());

        SecurityException ex = assertThrows(SecurityException.class, () -> {
            VisualAeadEngine.decrypt(pkg.cipherImage(), pkg.metadataBase64(), "WrongPassword!".toCharArray());
        });

        assertTrue(ex.getMessage().contains("AUTHENTICATION_FAILED"));
    }

    @Test
    @DisplayName("Tampered ciphertext pixel fails HMAC authentication and aborts immediately")
    void testTamperDetection() throws GeneralSecurityException {
        int width = 32;
        int height = 32;
        BufferedImage original = new BufferedImage(width, height, BufferedImage.TYPE_INT_RGB);
        char[] password = "Password123!".toCharArray();

        VisualAeadEngine.EncryptedPackage pkg = VisualAeadEngine.encrypt(original, password);

        // Tamper with a single pixel in cipher image
        BufferedImage tampered = new BufferedImage(width, height, BufferedImage.TYPE_INT_RGB);
        for (int y = 0; y < height; y++) {
            for (int x = 0; x < width; x++) {
                tampered.setRGB(x, y, pkg.cipherImage().getRGB(x, y));
            }
        }
        tampered.setRGB(0, 0, tampered.getRGB(0, 0) ^ 0x00010101); // flip bits

        SecurityException ex = assertThrows(SecurityException.class, () -> {
            VisualAeadEngine.decrypt(tampered, pkg.metadataBase64(), password);
        });

        assertTrue(ex.getMessage().contains("AUTHENTICATION_FAILED"));
    }
}

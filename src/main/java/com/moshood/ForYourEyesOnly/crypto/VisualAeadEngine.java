package com.moshood.ForYourEyesOnly.crypto;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

/**
 * F.Y.E.O Visual AEAD Engine (v2.0).
 * Implements Format-Preserving Authenticated Visual Encryption using:
 * - PBKDF2-HMAC-SHA256 (100,000 rounds)
 * - HKDF-Expand key separation
 * - AES-256-CTR CSPRNG keystream generator
 * - Unbiased Fisher-Yates pixel permutation
 * - Per-pixel RGB keystream diffusion
 * - HMAC-SHA256 authentication tag with constant-time verification
 */
public final class VisualAeadEngine {

    private static final byte[] MAGIC = new byte[]{'F', 'Y', 'E', 'O'};
    private static final byte VERSION = 0x02;
    private static final int PBKDF2_ITERATIONS = 100_000;
    private static final int SALT_BYTES = 16;
    private static final int NONCE_BYTES = 12;
    private static final int TAG_BYTES = 32;

    private static final SecureRandom CSPRNG = new SecureRandom();

    public static final int ENVELOPE_BYTE_LENGTH = 73;

    public record MetadataEnvelope(
            byte[] magic,
            byte version,
            byte[] salt,
            byte[] nonce,
            int width,
            int height,
            byte[] hmacTag
    ) {
        public MetadataEnvelope {
            magic = magic != null ? magic.clone() : new byte[0];
            salt = salt != null ? salt.clone() : new byte[0];
            nonce = nonce != null ? nonce.clone() : new byte[0];
            hmacTag = hmacTag != null ? hmacTag.clone() : new byte[0];
        }

        public byte[] magic() { return magic.clone(); }
        public byte[] salt() { return salt.clone(); }
        public byte[] nonce() { return nonce.clone(); }
        public byte[] hmacTag() { return hmacTag.clone(); }

        public byte[] toByteArray() {
            ByteBuffer buf = ByteBuffer.allocate(ENVELOPE_BYTE_LENGTH).order(ByteOrder.BIG_ENDIAN);
            buf.put(magic);
            buf.put(version);
            buf.put(salt);
            buf.put(nonce);
            buf.putInt(width);
            buf.putInt(height);
            buf.put(hmacTag);
            return buf.array();
        }

        public static MetadataEnvelope fromByteArray(byte[] envelopeBytes) {
            if (envelopeBytes == null || envelopeBytes.length != ENVELOPE_BYTE_LENGTH) {
                throw new SecurityException("MALFORMED_METADATA_CONTAINER");
            }
            ByteBuffer buf = ByteBuffer.wrap(envelopeBytes).order(ByteOrder.BIG_ENDIAN);
            byte[] magic = new byte[4];
            buf.get(magic);
            if (!Arrays.equals(magic, MAGIC)) {
                throw new SecurityException("UNRECOGNIZED_CONTAINER_MAGIC");
            }
            byte version = buf.get();
            if (version != VERSION) {
                throw new SecurityException("UNSUPPORTED_PROTOCOL_VERSION");
            }
            byte[] salt = new byte[SALT_BYTES];
            buf.get(salt);
            byte[] nonce = new byte[NONCE_BYTES];
            buf.get(nonce);
            int width = buf.getInt();
            int height = buf.getInt();
            byte[] hmacTag = new byte[TAG_BYTES];
            buf.get(hmacTag);
            return new MetadataEnvelope(magic, version, salt, nonce, width, height, hmacTag);
        }

        public static MetadataEnvelope fromBase64(String metadataBase64) {
            if (metadataBase64 == null) {
                throw new SecurityException("MALFORMED_METADATA_CONTAINER");
            }
            byte[] envelopeBytes = Base64.getDecoder().decode(metadataBase64);
            return fromByteArray(envelopeBytes);
        }

        public String toBase64() {
            return Base64.getEncoder().encodeToString(toByteArray());
        }
    }

    public record EncryptedPackage(
            BufferedImage cipherImage,
            byte[] salt,
            byte[] nonce,
            byte[] hmacTag,
            String metadataBase64
    ) {}

    /**
     * Encrypts a source image into a format-preserving encrypted PNG buffer.
     */
    public static EncryptedPackage encrypt(BufferedImage source, char[] password) throws GeneralSecurityException {
        int width = source.getWidth();
        int height = source.getHeight();
        int totalPixels = width * height;

        // 1. Generate fresh CSPRNG Salt and Nonce
        byte[] salt = new byte[SALT_BYTES];
        byte[] nonce = new byte[NONCE_BYTES];
        CSPRNG.nextBytes(salt);
        CSPRNG.nextBytes(nonce);

        // 2. Derive Master Key and Separated Subkeys
        byte[] masterKey = deriveMasterKey(password, salt);
        byte[] kPerm = hkdfExpand(masterKey, "FYEO-v2-Permutation".getBytes(StandardCharsets.UTF_8), 32);
        byte[] kDiff = hkdfExpand(masterKey, "FYEO-v2-Diffusion".getBytes(StandardCharsets.UTF_8), 32);
        byte[] kAuth = hkdfExpand(masterKey, "FYEO-v2-Auth-HMAC".getBytes(StandardCharsets.UTF_8), 32);

        // 3. Extract pixels into flat 1D ARGB array
        int[] pixels = source.getRGB(0, 0, width, height, null, 0, width);

        // 4. Perform unbiased Fisher-Yates permutation driven by AES-CTR keystream
        KeystreamGenerator permStream = new KeystreamGenerator(kPerm, nonce);
        for (int i = totalPixels - 1; i > 0; i--) {
            int j = permStream.nextUniformInt(i + 1);
            int tmp = pixels[i];
            pixels[i] = pixels[j];
            pixels[j] = tmp;
        }

        // 5. Perform per-pixel RGB keystream diffusion
        KeystreamGenerator diffStream = new KeystreamGenerator(kDiff, nonce);
        byte[] diffBuffer = new byte[totalPixels * 3];
        diffStream.fillBytes(diffBuffer);

        for (int i = 0; i < totalPixels; i++) {
            int argb = pixels[i];
            int r = ((argb >> 16) & 0xFF) ^ (diffBuffer[i * 3] & 0xFF);
            int g = ((argb >> 8) & 0xFF) ^ (diffBuffer[i * 3 + 1] & 0xFF);
            int b = (argb & 0xFF) ^ (diffBuffer[i * 3 + 2] & 0xFF);
            pixels[i] = (0xFF << 24) | (r << 16) | (g << 8) | b;
        }

        // 6. Build BufferedImage container
        BufferedImage cipherImage = new BufferedImage(width, height, BufferedImage.TYPE_INT_RGB);
        cipherImage.setRGB(0, 0, width, height, pixels, 0, width);

        // 7. Calculate HMAC-SHA256 authentication tag over AAD || Pixels
        byte[] aad = buildAad(salt, nonce, width, height);
        byte[] pixelBytes = intsToBytes(pixels);
        byte[] tag = computeHmacSha256(kAuth, aad, pixelBytes);

        // 8. Package metadata envelope for PNG tEXt insertion
        MetadataEnvelope envelope = new MetadataEnvelope(MAGIC, VERSION, salt, nonce, width, height, tag);
        String metadataBase64 = envelope.toBase64();

        // Zero sensitive subkeys in memory
        Arrays.fill(masterKey, (byte) 0);
        Arrays.fill(kPerm, (byte) 0);
        Arrays.fill(kDiff, (byte) 0);
        Arrays.fill(kAuth, (byte) 0);

        return new EncryptedPackage(cipherImage, salt, nonce, tag, metadataBase64);
    }

    /**
     * Decrypts a cipher image after validating authentication tag in constant time.
     */
    public static BufferedImage decrypt(BufferedImage cipherImage, String metadataBase64, char[] password)
            throws GeneralSecurityException {

        MetadataEnvelope envelope = MetadataEnvelope.fromBase64(metadataBase64);
        byte[] salt = envelope.salt();
        byte[] nonce = envelope.nonce();
        int expectedWidth = envelope.width();
        int expectedHeight = envelope.height();
        byte[] expectedTag = envelope.hmacTag();

        int width = cipherImage.getWidth();
        int height = cipherImage.getHeight();
        if (width != expectedWidth || height != expectedHeight) {
            throw new SecurityException("IMAGE_DIMENSIONS_MISMATCH_OR_CROPPED");
        }
        int totalPixels = width * height;

        // 1. Re-derive keys
        byte[] masterKey = deriveMasterKey(password, salt);
        byte[] kAuth = hkdfExpand(masterKey, "FYEO-v2-Auth-HMAC".getBytes(StandardCharsets.UTF_8), 32);

        // 2. Extract pixels and compute candidate HMAC tag
        int[] pixels = cipherImage.getRGB(0, 0, width, height, null, 0, width);
        byte[] aad = buildAad(salt, nonce, width, height);
        byte[] pixelBytes = intsToBytes(pixels);
        byte[] candidateTag = computeHmacSha256(kAuth, aad, pixelBytes);

        // 3. Constant-time authentication tag verification
        if (!MessageDigest.isEqual(expectedTag, candidateTag)) {
            Arrays.fill(masterKey, (byte) 0);
            Arrays.fill(kAuth, (byte) 0);
            throw new SecurityException("AUTHENTICATION_FAILED_WRONG_KEY_OR_TAMPERED");
        }

        // 4. Derive decryption keystreams
        byte[] kDiff = hkdfExpand(masterKey, "FYEO-v2-Diffusion".getBytes(StandardCharsets.UTF_8), 32);
        byte[] kPerm = hkdfExpand(masterKey, "FYEO-v2-Permutation".getBytes(StandardCharsets.UTF_8), 32);

        // 5. Invert per-pixel RGB keystream diffusion
        KeystreamGenerator diffStream = new KeystreamGenerator(kDiff, nonce);
        byte[] diffBuffer = new byte[totalPixels * 3];
        diffStream.fillBytes(diffBuffer);

        for (int i = 0; i < totalPixels; i++) {
            int argb = pixels[i];
            int r = ((argb >> 16) & 0xFF) ^ (diffBuffer[i * 3] & 0xFF);
            int g = ((argb >> 8) & 0xFF) ^ (diffBuffer[i * 3 + 1] & 0xFF);
            int b = (argb & 0xFF) ^ (diffBuffer[i * 3 + 2] & 0xFF);
            pixels[i] = (0xFF << 24) | (r << 16) | (g << 8) | b;
        }

        // 6. Invert Fisher-Yates permutation
        // Record forward swap trajectory using identical seed keystream
        KeystreamGenerator permStream = new KeystreamGenerator(kPerm, nonce);
        int[] swapTarget = new int[totalPixels];
        for (int i = totalPixels - 1; i > 0; i--) {
            swapTarget[i] = permStream.nextUniformInt(i + 1);
        }

        // Replay swaps in reverse chronological order
        for (int i = 1; i < totalPixels; i++) {
            int j = swapTarget[i];
            int tmp = pixels[i];
            pixels[i] = pixels[j];
            pixels[j] = tmp;
        }

        // 7. Output decrypted BufferedImage
        BufferedImage plainImage = new BufferedImage(width, height, BufferedImage.TYPE_INT_RGB);
        plainImage.setRGB(0, 0, width, height, pixels, 0, width);

        Arrays.fill(masterKey, (byte) 0);
        Arrays.fill(kAuth, (byte) 0);
        Arrays.fill(kDiff, (byte) 0);
        Arrays.fill(kPerm, (byte) 0);

        return plainImage;
    }

    private static byte[] deriveMasterKey(char[] password, byte[] salt) throws GeneralSecurityException {
        PBEKeySpec spec = new PBEKeySpec(password, salt, PBKDF2_ITERATIONS, 256);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] key = skf.generateSecret(spec).getEncoded();
        spec.clearPassword();
        return key;
    }

    private static byte[] hkdfExpand(byte[] prk, byte[] info, int outputLength) throws GeneralSecurityException {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(prk, "HmacSHA256"));
        ByteArrayOutputStream okm = new ByteArrayOutputStream();
        byte[] t = new byte[0];
        byte counter = 1;

        while (okm.size() < outputLength) {
            mac.update(t);
            mac.update(info);
            mac.update(counter);
            t = mac.doFinal();
            int toWrite = Math.min(t.length, outputLength - okm.size());
            okm.write(t, 0, toWrite);
            counter++;
        }
        return okm.toByteArray();
    }

    private static byte[] buildAad(byte[] salt, byte[] nonce, int width, int height) {
        ByteBuffer buf = ByteBuffer.allocate(4 + 1 + SALT_BYTES + NONCE_BYTES + 4 + 4).order(ByteOrder.BIG_ENDIAN);
        buf.put(MAGIC);
        buf.put(VERSION);
        buf.put(salt);
        buf.put(nonce);
        buf.putInt(width);
        buf.putInt(height);
        return buf.array();
    }

    private static byte[] computeHmacSha256(byte[] key, byte[] aad, byte[] data) throws GeneralSecurityException {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        mac.update(aad);
        mac.update(data);
        return mac.doFinal();
    }

    private static byte[] intsToBytes(int[] ints) {
        ByteBuffer buf = ByteBuffer.allocate(ints.length * 4).order(ByteOrder.BIG_ENDIAN);
        for (int val : ints) buf.putInt(val);
        return buf.array();
    }

    /**
     * High-speed AES-256-CTR Keystream Generator for unbiased Fisher-Yates and RGB diffusion.
     */
    private static final class KeystreamGenerator {
        private final Cipher cipher;
        private final byte[] counterBlock = new byte[16];
        private final byte[] buffer = new byte[4096];
        private int bufferPos = 4096;
        private long blockCounter = 0;

        KeystreamGenerator(byte[] key, byte[] nonce96) throws GeneralSecurityException {
            this.cipher = Cipher.getInstance("AES/ECB/NoPadding");
            this.cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"));
            System.arraycopy(nonce96, 0, counterBlock, 0, 12);
        }

        private void refillBuffer() {
            try {
                int blocks = buffer.length / 16;
                for (int b = 0; b < blocks; b++) {
                    counterBlock[12] = (byte) (blockCounter >> 24);
                    counterBlock[13] = (byte) (blockCounter >> 16);
                    counterBlock[14] = (byte) (blockCounter >> 8);
                    counterBlock[15] = (byte) blockCounter;
                    blockCounter++;
                    cipher.doFinal(counterBlock, 0, 16, buffer, b * 16);
                }
                bufferPos = 0;
            } catch (GeneralSecurityException e) {
                throw new RuntimeException("KEYSTREAM_GENERATION_FAILED", e);
            }
        }

        public byte nextByte() {
            if (bufferPos >= buffer.length) refillBuffer();
            return buffer[bufferPos++];
        }

        public void fillBytes(byte[] out) {
            int offset = 0;
            while (offset < out.length) {
                if (bufferPos >= buffer.length) refillBuffer();
                int chunk = Math.min(buffer.length - bufferPos, out.length - offset);
                System.arraycopy(buffer, bufferPos, out, offset, chunk);
                bufferPos += chunk;
                offset += chunk;
            }
        }

        public int nextUniformInt(int bound) {
            if (bound <= 1) return 0;
            long boundLong = bound;
            long threshold = (1L << 32) - ((1L << 32) % boundLong);
            while (true) {
                long word = ((long) (nextByte() & 0xFF) << 24)
                          | ((long) (nextByte() & 0xFF) << 16)
                          | ((long) (nextByte() & 0xFF) << 8)
                          | ((long) (nextByte() & 0xFF));
                word &= 0xFFFFFFFFL;
                if (word < threshold) {
                    return (int) (word % boundLong);
                }
            }
        }
    }
}

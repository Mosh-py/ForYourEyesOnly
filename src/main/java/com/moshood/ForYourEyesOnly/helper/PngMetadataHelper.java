package com.moshood.ForYourEyesOnly.helper;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.Optional;
import java.util.zip.CRC32;

import com.moshood.ForYourEyesOnly.exception.CorruptedImageException;

/**
 * Pure Java PNG chunk injector and extractor compliant with ISO/IEC 15948 / RFC 2083.
 * Supports injecting and extracting tEXt ancillary chunks (e.g. "fyeO") with CRC32 integrity validation.
 */
public final class PngMetadataHelper {

    private static final byte[] PNG_SIGNATURE = new byte[]{
            (byte) 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A
    };
    private static final byte[] TEXT_CHUNK_TYPE = new byte[]{'t', 'E', 'X', 't'};

    private PngMetadataHelper() {
        // Utility class
    }

    /**
     * Checks if the given byte array starts with the standard 8-byte PNG file signature.
     *
     * @param data the byte array to check
     * @return true if valid PNG signature, false otherwise
     */
    public static boolean hasPngSignature(byte[] data) {
        if (data == null || data.length < 8) {
            return false;
        }
        for (int i = 0; i < 8; i++) {
            if (data[i] != PNG_SIGNATURE[i]) {
                return false;
            }
        }
        return true;
    }

    /**
     * Alias for hasPngSignature.
     */
    public static boolean isValidPng(byte[] data) {
        return hasPngSignature(data);
    }

    /**
     * Injects a compliant tEXt chunk before the IEND chunk in the given PNG byte array.
     *
     * @param pngBytes  the source PNG byte array
     * @param keyword   the tEXt chunk keyword (1-79 characters, Latin-1)
     * @param textValue the text value to embed (Latin-1 / ASCII / Base64)
     * @return a new byte array containing the PNG with the injected tEXt chunk
     */
    public static byte[] injectTextChunk(byte[] pngBytes, String keyword, String textValue) {
        if (pngBytes == null || pngBytes.length < 8) {
            throw new IllegalArgumentException("Invalid PNG data: data is null or shorter than PNG signature");
        }
        if (!hasPngSignature(pngBytes)) {
            throw new IllegalArgumentException("Invalid PNG signature: input is not a valid PNG image");
        }
        if (keyword == null || keyword.isEmpty() || keyword.length() > 79) {
            throw new IllegalArgumentException("PNG tEXt keyword must be between 1 and 79 characters");
        }
        if (textValue == null) {
            throw new IllegalArgumentException("textValue must not be null");
        }

        // Locate IEND chunk
        int offset = 8;
        int iendOffset = -1;

        while (offset + 8 <= pngBytes.length) {
            int length = ByteBuffer.wrap(pngBytes, offset, 4).getInt();
            if (length < 0) {
                throw new IllegalArgumentException("Invalid PNG chunk length: " + length);
            }
            if (offset + 12 + length > pngBytes.length) {
                throw new IllegalArgumentException("Truncated PNG data encountered while locating IEND chunk");
            }

            String chunkType = new String(pngBytes, offset + 4, 4, StandardCharsets.US_ASCII);
            if ("IEND".equals(chunkType)) {
                iendOffset = offset;
                break;
            }
            offset += 12 + length;
        }

        if (iendOffset == -1) {
            throw new IllegalArgumentException("Invalid PNG: IEND chunk not found");
        }

        // Construct tEXt chunk data: keyword + 0x00 (null separator) + textValue
        byte[] keywordBytes = keyword.getBytes(StandardCharsets.ISO_8859_1);
        byte[] textBytes = textValue.getBytes(StandardCharsets.ISO_8859_1);
        int chunkDataLength = keywordBytes.length + 1 + textBytes.length;

        byte[] chunkData = new byte[chunkDataLength];
        System.arraycopy(keywordBytes, 0, chunkData, 0, keywordBytes.length);
        chunkData[keywordBytes.length] = 0; // null separator
        System.arraycopy(textBytes, 0, chunkData, keywordBytes.length + 1, textBytes.length);

        // Calculate CRC32 over chunk type and chunk data
        CRC32 crc = new CRC32();
        crc.update(TEXT_CHUNK_TYPE);
        crc.update(chunkData);
        int crcValue = (int) crc.getValue();

        // Assemble tEXt chunk bytes: 4 bytes length + 4 bytes type + chunkDataLength bytes data + 4 bytes CRC
        ByteBuffer chunkBuffer = ByteBuffer.allocate(12 + chunkDataLength).order(ByteOrder.BIG_ENDIAN);
        chunkBuffer.putInt(chunkDataLength);
        chunkBuffer.put(TEXT_CHUNK_TYPE);
        chunkBuffer.put(chunkData);
        chunkBuffer.putInt(crcValue);
        byte[] tEXtChunkBytes = chunkBuffer.array();

        // Construct result: pngBytes[0..iendOffset] + tEXtChunkBytes + pngBytes[iendOffset..end]
        byte[] output = new byte[pngBytes.length + tEXtChunkBytes.length];
        System.arraycopy(pngBytes, 0, output, 0, iendOffset);
        System.arraycopy(tEXtChunkBytes, 0, output, iendOffset, tEXtChunkBytes.length);
        System.arraycopy(pngBytes, iendOffset, output, iendOffset + tEXtChunkBytes.length, pngBytes.length - iendOffset);

        return output;
    }

    /**
     * Walks PNG chunks and extracts the text value for the given keyword.
     * Supports both standard tEXt chunks with keyword and custom ancillary chunks matching the keyword.
     * Validates CRC32 on the matching chunk and throws CorruptedImageException if CRC is invalid.
     *
     * @param pngBytes the PNG byte array
     * @param keyword  the keyword to search for
     * @return Optional containing the text value if found, or Optional.empty() if missing or invalid
     */
    public static Optional<String> extractTextChunk(byte[] pngBytes, String keyword) {
        if (pngBytes == null || pngBytes.length < 8 || keyword == null || keyword.isEmpty()) {
            return Optional.empty();
        }
        if (!hasPngSignature(pngBytes)) {
            return Optional.empty();
        }

        int offset = 8;
        while (offset + 12 <= pngBytes.length) {
            int length = ByteBuffer.wrap(pngBytes, offset, 4).getInt();
            if (length < 0 || offset + 12 + length > pngBytes.length) {
                break;
            }

            String chunkType = new String(pngBytes, offset + 4, 4, StandardCharsets.US_ASCII);
            if ("tEXt".equals(chunkType)) {
                // Find null separator within chunk data (from offset + 8 to offset + 8 + length)
                int dataStart = offset + 8;
                int nullIndex = -1;
                for (int i = dataStart; i < dataStart + length; i++) {
                    if (pngBytes[i] == 0) {
                        nullIndex = i;
                        break;
                    }
                }

                if (nullIndex != -1) {
                    int keywordLen = nullIndex - dataStart;
                    String foundKeyword = new String(pngBytes, dataStart, keywordLen, StandardCharsets.ISO_8859_1);
                    if (foundKeyword.equals(keyword)) {
                        // Verify CRC32
                        CRC32 crc = new CRC32();
                        crc.update(pngBytes, offset + 4, 4 + length);
                        int expectedCrc = (int) crc.getValue();
                        int actualCrc = ByteBuffer.wrap(pngBytes, offset + 8 + length, 4).getInt();
                        if (expectedCrc != actualCrc) {
                            throw new CorruptedImageException("Corrupted PNG: CRC32 checksum mismatch in '" + keyword + "' metadata chunk");
                        }

                        int textStart = nullIndex + 1;
                        int textLength = (dataStart + length) - textStart;
                        String textValue = new String(pngBytes, textStart, textLength, StandardCharsets.ISO_8859_1);
                        return Optional.of(textValue);
                    }
                }
            } else if (chunkType.equals(keyword)) {
                // Support custom ancillary chunk matching keyword directly
                CRC32 crc = new CRC32();
                crc.update(pngBytes, offset + 4, 4 + length);
                int expectedCrc = (int) crc.getValue();
                int actualCrc = ByteBuffer.wrap(pngBytes, offset + 8 + length, 4).getInt();
                if (expectedCrc != actualCrc) {
                    throw new CorruptedImageException("Corrupted PNG: CRC32 checksum mismatch in '" + keyword + "' metadata chunk");
                }
                String textValue = new String(pngBytes, offset + 8, length, StandardCharsets.ISO_8859_1);
                return Optional.of(textValue);
            } else if ("IEND".equals(chunkType)) {
                break;
            }

            offset += 12 + length;
        }

        return Optional.empty();
    }

    /**
     * Convenience method returning the extracted text value or null if absent.
     */
    public static String extractTextChunkOrNull(byte[] pngBytes, String keyword) {
        return extractTextChunk(pngBytes, keyword).orElse(null);
    }
}

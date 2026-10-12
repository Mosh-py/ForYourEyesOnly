/**
 * F.Y.E.O Visual AEAD Engine (v2.0) - Dedicated Web Worker
 * Pure client-side zero-knowledge visual encryption and decryption.
 *
 * Implements:
 * - PBKDF2-HMAC-SHA256 (100,000 rounds)
 * - RFC 5869 HKDF-Expand key separation
 * - AES-256-CTR CSPRNG keystream generator with 32-bit counter
 * - Unbiased Fisher-Yates pixel permutation with rejection sampling
 * - Per-pixel continuous RGB keystream diffusion
 * - HMAC-SHA256 authentication tag with constant-time verification
 * - ISO/IEC 15948 compliant PNG tEXt chunk injector/extractor with pure JS CRC32
 * - OffscreenCanvas non-blocking pixel manipulation
 */

// Custom Error Class
class FyeoError extends Error {
    constructor(message, code) {
        super(message);
        this.name = 'FyeoError';
        this.code = code || 'CRYPTO_ERROR';
    }
}

// 1. IEEE 802.3 CRC32 Implementation
const CRC32_TABLE = new Uint32Array(256);
for (let i = 0; i < 256; i++) {
    let c = i;
    for (let k = 0; k < 8; k++) {
        c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
    }
    CRC32_TABLE[i] = c >>> 0;
}

function crc32(buffer, offset = 0, length = buffer.length) {
    let crc = 0xFFFFFFFF;
    const end = offset + length;
    for (let i = offset; i < end; i++) {
        crc = (crc >>> 8) ^ CRC32_TABLE[(crc ^ buffer[i]) & 0xFF];
    }
    return (crc ^ 0xFFFFFFFF) >>> 0;
}

// 2. Base64 & Binary Utilities
function uint8ArrayToBase64(bytes) {
    let binary = '';
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}

function base64ToUint8Array(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
}

function constantTimeEqual(a, b) {
    if (a.byteLength !== b.byteLength) return false;
    let diff = 0;
    for (let i = 0; i < a.byteLength; i++) {
        diff |= a[i] ^ b[i];
    }
    return diff === 0;
}

// 3. PNG Metadata Container Helper (ISO/IEC 15948 / RFC 2083)
class PngChunkHelper {
    static PNG_SIGNATURE = new Uint8Array([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);
    static TEXT_CHUNK_TYPE = new Uint8Array([0x74, 0x45, 0x58, 0x74]); // 'tEXt'

    static hasPngSignature(bytes) {
        if (!bytes || bytes.length < 8) return false;
        for (let i = 0; i < 8; i++) {
            if (bytes[i] !== this.PNG_SIGNATURE[i]) return false;
        }
        return true;
    }

    /**
     * Extracts keyword text from tEXt or custom ancillary chunk matching keyword.
     * Validates CRC32 integrity.
     */
    static extractTextChunk(pngBytes, keyword) {
        if (!this.hasPngSignature(pngBytes) || !keyword) return null;

        const view = new DataView(pngBytes.buffer, pngBytes.byteOffset, pngBytes.byteLength);
        let offset = 8;

        while (offset + 12 <= pngBytes.length) {
            const length = view.getUint32(offset, false);
            if (length < 0 || offset + 12 + length > pngBytes.length) break;

            const chunkType = String.fromCharCode(...pngBytes.subarray(offset + 4, offset + 8));

            if (chunkType === 'tEXt') {
                const dataStart = offset + 8;
                let nullIdx = -1;
                for (let i = dataStart; i < dataStart + length; i++) {
                    if (pngBytes[i] === 0) {
                        nullIdx = i;
                        break;
                    }
                }

                if (nullIdx !== -1) {
                    const kw = String.fromCharCode(...pngBytes.subarray(dataStart, nullIdx));
                    if (kw === keyword) {
                        // Check CRC32
                        const expectedCrc = view.getUint32(offset + 8 + length, false);
                        const actualCrc = crc32(pngBytes, offset + 4, 4 + length);
                        if (expectedCrc !== actualCrc) {
                            throw new FyeoError(
                                `Corrupted PNG: CRC32 mismatch in '${keyword}' metadata chunk`,
                                'CORRUPTED_PNG_CRC_MISMATCH'
                            );
                        }
                        const textBytes = pngBytes.subarray(nullIdx + 1, dataStart + length);
                        let text = '';
                        for (let t = 0; t < textBytes.length; t++) {
                            text += String.fromCharCode(textBytes[t]);
                        }
                        return text;
                    }
                }
            } else if (chunkType === keyword) {
                // Support custom ancillary chunk named keyword directly
                const expectedCrc = view.getUint32(offset + 8 + length, false);
                const actualCrc = crc32(pngBytes, offset + 4, 4 + length);
                if (expectedCrc !== actualCrc) {
                    throw new FyeoError(
                        `Corrupted PNG: CRC32 mismatch in '${keyword}' metadata chunk`,
                        'CORRUPTED_PNG_CRC_MISMATCH'
                    );
                }
                const textBytes = pngBytes.subarray(offset + 8, offset + 8 + length);
                let text = '';
                for (let t = 0; t < textBytes.length; t++) {
                    text += String.fromCharCode(textBytes[t]);
                }
                return text;
            } else if (chunkType === 'IEND') {
                break;
            }

            offset += 12 + length;
        }

        return null;
    }

    /**
     * Injects a compliant tEXt chunk directly before the IEND chunk with valid CRC32.
     */
    static injectTextChunk(pngBytes, keyword, textValue) {
        if (!this.hasPngSignature(pngBytes)) {
            throw new FyeoError('Invalid PNG: Missing standard 8-byte PNG signature', 'INVALID_PNG');
        }
        if (!keyword || keyword.length > 79) {
            throw new FyeoError('Invalid keyword length (must be 1-79 characters)', 'INVALID_KEYWORD');
        }

        const view = new DataView(pngBytes.buffer, pngBytes.byteOffset, pngBytes.byteLength);
        let offset = 8;
        let iendOffset = -1;

        while (offset + 8 <= pngBytes.length) {
            const length = view.getUint32(offset, false);
            if (offset + 12 + length > pngBytes.length) {
                throw new FyeoError('Truncated PNG encountered while locating IEND chunk', 'TRUNCATED_PNG');
            }
            const chunkType = String.fromCharCode(...pngBytes.subarray(offset + 4, offset + 8));
            if (chunkType === 'IEND') {
                iendOffset = offset;
                break;
            }
            offset += 12 + length;
        }

        if (iendOffset === -1) {
            throw new FyeoError('Invalid PNG: IEND chunk not found', 'MISSING_IEND');
        }

        const keyBytes = new Uint8Array(keyword.length);
        for (let i = 0; i < keyword.length; i++) keyBytes[i] = keyword.charCodeAt(i);

        const valBytes = new Uint8Array(textValue.length);
        for (let i = 0; i < textValue.length; i++) valBytes[i] = textValue.charCodeAt(i);

        const chunkDataLength = keyBytes.length + 1 + valBytes.length;
        const chunkBytes = new Uint8Array(12 + chunkDataLength);
        const chunkView = new DataView(chunkBytes.buffer);

        // 4 bytes Length
        chunkView.setUint32(0, chunkDataLength, false);
        // 4 bytes Type 'tEXt'
        chunkBytes.set(this.TEXT_CHUNK_TYPE, 4);
        // Keyword + null byte + textValue
        chunkBytes.set(keyBytes, 8);
        chunkBytes[8 + keyBytes.length] = 0; // null separator
        chunkBytes.set(valBytes, 8 + keyBytes.length + 1);

        // 4 bytes CRC32 over chunk type and data
        const crc = crc32(chunkBytes, 4, 4 + chunkDataLength);
        chunkView.setUint32(8 + chunkDataLength, crc, false);

        // Assemble result
        const result = new Uint8Array(pngBytes.length + chunkBytes.length);
        result.set(pngBytes.subarray(0, iendOffset), 0);
        result.set(chunkBytes, iendOffset);
        result.set(pngBytes.subarray(iendOffset), iendOffset + chunkBytes.length);

        return result;
    }
}

// 4. AES-CTR Keystream Generator (Unbiased Fisher-Yates & RGB Diffusion)
class WebKeystreamGenerator {
    constructor(cryptoKey, nonce96) {
        this.cryptoKey = cryptoKey;
        this.nonce96 = nonce96;
        this.buffer = new Uint8Array(0);
        this.bufferPos = 0;
        this.blockCounter = 0;
    }

    async refillBuffer(minBytes = 65536) {
        const blocks = Math.ceil(minBytes / 16);
        const byteLen = blocks * 16;
        const counterBlock = new Uint8Array(16);
        counterBlock.set(this.nonce96, 0);
        const view = new DataView(counterBlock.buffer);
        view.setUint32(12, this.blockCounter, false);
        this.blockCounter += blocks;

        const zero = new Uint8Array(byteLen);
        const enc = await crypto.subtle.encrypt(
            { name: 'AES-CTR', counter: counterBlock, length: 32 },
            this.cryptoKey,
            zero
        );
        this.buffer = new Uint8Array(enc);
        this.bufferPos = 0;
    }

    async nextUniformInt(bound) {
        if (bound <= 1) return 0;
        // Exact 64-bit threshold calculation matching Java
        const threshold = 4294967296 - (4294967296 % bound);
        while (true) {
            if (this.bufferPos + 4 > this.buffer.length) {
                await this.refillBuffer(65536);
            }
            const b0 = this.buffer[this.bufferPos++];
            const b1 = this.buffer[this.bufferPos++];
            const b2 = this.buffer[this.bufferPos++];
            const b3 = this.buffer[this.bufferPos++];
            const word = ((b0 << 24) >>> 0) + (b1 << 16) + (b2 << 8) + b3;
            if (word < threshold) {
                return word % bound;
            }
        }
    }
}

// 5. Visual AEAD Engine (Core Cryptography)
class VisualAeadWorkerEngine {
    static MAGIC = new Uint8Array([0x46, 0x59, 0x45, 0x4F]); // 'FYEO'
    static VERSION_V2 = 0x02; // Symmetric Passphrase Mode
    static VERSION_V3 = 0x03; // Asymmetric Device-to-Device ECDH Mode
    static PBKDF2_ROUNDS = 100000;
    static SALT_BYTES = 16;
    static NONCE_BYTES = 12;
    static TAG_BYTES = 32;
    static ENVELOPE_V2_BYTE_LENGTH = 73;
    static ENVELOPE_V3_BYTE_LENGTH = 138; // 4 Magic + 1 Ver + 16 Salt + 12 Nonce + 4 W + 4 H + 65 EphPub + 32 Tag

    static async deriveMasterKey(password, salt) {
        const enc = new TextEncoder();
        const baseKey = await crypto.subtle.importKey(
            'raw',
            enc.encode(password),
            'PBKDF2',
            false,
            ['deriveBits']
        );
        const masterBits = await crypto.subtle.deriveBits(
            {
                name: 'PBKDF2',
                salt: salt,
                iterations: this.PBKDF2_ROUNDS,
                hash: 'SHA-256'
            },
            baseKey,
            256
        );
        return new Uint8Array(masterBits);
    }

    /**
     * Derives master key via ECDH (P-256) + HKDF-Extract.
     */
    static async deriveMasterKeyFromEcdh(privateKey, recipientPublicKeyRaw, salt) {
        const importedPub = await crypto.subtle.importKey(
            'raw',
            recipientPublicKeyRaw,
            { name: 'ECDH', namedCurve: 'P-256' },
            false,
            []
        );

        const sharedBits = await crypto.subtle.deriveBits(
            {
                name: 'ECDH',
                public: importedPub
            },
            privateKey,
            256
        );

        // HKDF-Extract with salt over shared secret bits
        const prkHmacKey = await crypto.subtle.importKey(
            'raw',
            salt,
            { name: 'HMAC', hash: 'SHA-256' },
            false,
            ['sign']
        );

        const prk = await crypto.subtle.sign('HMAC', prkHmacKey, sharedBits);
        return new Uint8Array(prk);
    }

    /**
     * Bit-for-bit parity with Java hkdfExpand(prk, info, 32).
     */
    static async hkdfExpand(prkBytes, infoString, outputLength = 32) {
        const enc = new TextEncoder();
        const infoBytes = enc.encode(infoString);
        const hmacKey = await crypto.subtle.importKey(
            'raw',
            prkBytes,
            { name: 'HMAC', hash: 'SHA-256' },
            false,
            ['sign']
        );
        const data = new Uint8Array(infoBytes.length + 1);
        data.set(infoBytes, 0);
        data[infoBytes.length] = 1; // counter = 1
        const sig = await crypto.subtle.sign('HMAC', hmacKey, data);
        return new Uint8Array(sig).subarray(0, outputLength);
    }

    static buildAadV2(salt, nonce, width, height) {
        const aad = new Uint8Array(4 + 1 + this.SALT_BYTES + this.NONCE_BYTES + 4 + 4);
        aad.set(this.MAGIC, 0);
        aad[4] = this.VERSION_V2;
        aad.set(salt, 5);
        aad.set(nonce, 21);
        const view = new DataView(aad.buffer);
        view.setUint32(33, width, false);
        view.setUint32(37, height, false);
        return aad;
    }

    static buildAadV3(salt, nonce, width, height, ephPub65) {
        const aad = new Uint8Array(4 + 1 + this.SALT_BYTES + this.NONCE_BYTES + 4 + 4 + 65);
        aad.set(this.MAGIC, 0);
        aad[4] = this.VERSION_V3;
        aad.set(salt, 5);
        aad.set(nonce, 21);
        const view = new DataView(aad.buffer);
        view.setUint32(33, width, false);
        view.setUint32(37, height, false);
        aad.set(ephPub65, 41);
        return aad;
    }

    /**
     * Converts RGBA Uint8ClampedArray to ARGB Big-Endian Uint8Array matching Java intsToBytes:
     * Byte 0: 0xFF (Alpha)
     * Byte 1: R
     * Byte 2: G
     * Byte 3: B
     */
    static buildArgbPixelBytes(rgbaData, totalPixels) {
        const pixelBytes = new Uint8Array(totalPixels * 4);
        for (let i = 0; i < totalPixels; i++) {
            pixelBytes[i * 4 + 0] = 0xFF;
            pixelBytes[i * 4 + 1] = rgbaData[i * 4 + 0]; // R
            pixelBytes[i * 4 + 2] = rgbaData[i * 4 + 1]; // G
            pixelBytes[i * 4 + 3] = rgbaData[i * 4 + 2]; // B
        }
        return pixelBytes;
    }

    /**
     * Full encryption routine executed in Web Worker.
     */
    /**
     * Full encryption routine executed in Web Worker.
     * Supports:
     * - Symmetric Passphrase Mode (v2): password string
     * - Asymmetric Public-Key Mode (v3): recipientPublicKey (Uint8Array / Base64)
     */
    static async encrypt(fileBlob, keyOrPassword, onProgress) {
        // 1. Decode source image
        onProgress(10, 'reading', 'Decoding source image in memory...');
        let bitmap;
        try {
            bitmap = await createImageBitmap(fileBlob, { colorSpaceConversion: 'none' });
        } catch (e) {
            bitmap = await createImageBitmap(fileBlob);
        }

        // Bounded dimension guardrail (prevents maximum-entropy encrypted PNGs from exploding into 70MB+)
        const MAX_DIMENSION = 1280;
        let width = bitmap.width;
        let height = bitmap.height;

        if (width > MAX_DIMENSION || height > MAX_DIMENSION) {
            const scale = MAX_DIMENSION / Math.max(width, height);
            width = Math.round(width * scale);
            height = Math.round(height * scale);
        }

        const totalPixels = width * height;

        const offscreen = new OffscreenCanvas(width, height);
        const ctx = offscreen.getContext('2d', { willReadFrequently: true });
        ctx.drawImage(bitmap, 0, 0, width, height);
        const imgData = ctx.getImageData(0, 0, width, height);

        // 2. CSPRNG Salt & Nonce
        const salt = crypto.getRandomValues(new Uint8Array(this.SALT_BYTES));
        const nonce = crypto.getRandomValues(new Uint8Array(this.NONCE_BYTES));

        // Determine Mode: Asymmetric v3 if keyOrPassword starts with "fyeo-pub-" or is 65-byte uncompressed pubkey
        let isAsymmetric = false;
        let recipientPubBytes = null;
        if (typeof keyOrPassword === 'string' && keyOrPassword.startsWith('fyeo-pub-')) {
            isAsymmetric = true;
            recipientPubBytes = base64ToUint8Array(keyOrPassword.substring(9));
        } else if (keyOrPassword instanceof Uint8Array && keyOrPassword.length === 65) {
            isAsymmetric = true;
            recipientPubBytes = keyOrPassword;
        }

        let masterKey;
        let ephPubBytes = null;
        let aad;

        if (isAsymmetric) {
            onProgress(25, 'kdf', 'Executing ECDH point multiplication & ephemeral key generation...');
            // Generate disposable ephemeral keypair (P-256)
            const ephKeyPair = await crypto.subtle.generateKey(
                { name: 'ECDH', namedCurve: 'P-256' },
                true,
                ['deriveKey', 'deriveBits']
            );
            ephPubBytes = new Uint8Array(await crypto.subtle.exportKey('raw', ephKeyPair.publicKey));
            masterKey = await this.deriveMasterKeyFromEcdh(ephKeyPair.privateKey, recipientPubBytes, salt);
            aad = this.buildAadV3(salt, nonce, width, height, ephPubBytes);
        } else {
            onProgress(25, 'kdf', 'Deriving cryptographic keys (PBKDF2 100,000 rounds)...');
            masterKey = await this.deriveMasterKey(keyOrPassword, salt);
            aad = this.buildAadV2(salt, nonce, width, height);
        }

        const kPermBytes = await this.hkdfExpand(masterKey, 'FYEO-v2-Permutation', 32);
        const kDiffBytes = await this.hkdfExpand(masterKey, 'FYEO-v2-Diffusion', 32);
        const kAuthBytes = await this.hkdfExpand(masterKey, 'FYEO-v2-Auth-HMAC', 32);

        const kPerm = await crypto.subtle.importKey('raw', kPermBytes, { name: 'AES-CTR' }, false, ['encrypt']);
        const kDiff = await crypto.subtle.importKey('raw', kDiffBytes, { name: 'AES-CTR' }, false, ['encrypt']);
        const kAuth = await crypto.subtle.importKey('raw', kAuthBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);

        // 4. Fisher-Yates Pixel Permutation
        onProgress(45, 'permute', 'Permuting pixels with AES-CTR Fisher-Yates shuffle...');
        const permGen = new WebKeystreamGenerator(kPerm, nonce);
        await permGen.refillBuffer(totalPixels * 4 + 65536);
        const pixel32 = new Uint32Array(imgData.data.buffer, imgData.data.byteOffset, totalPixels);

        for (let i = totalPixels - 1; i > 0; i--) {
            const j = await permGen.nextUniformInt(i + 1);
            const tmp = pixel32[i];
            pixel32[i] = pixel32[j];
            pixel32[j] = tmp;
        }

        // 5. RGB Keystream Diffusion
        onProgress(65, 'diffuse', 'Applying continuous RGB keystream diffusion...');
        const counterBlock = new Uint8Array(16);
        counterBlock.set(nonce, 0);
        const zeroPlaintext = new Uint8Array(totalPixels * 3);
        const diffKeystream = new Uint8Array(await crypto.subtle.encrypt(
            { name: 'AES-CTR', counter: counterBlock, length: 32 },
            kDiff,
            zeroPlaintext
        ));

        for (let i = 0; i < totalPixels; i++) {
            imgData.data[i * 4 + 0] ^= diffKeystream[i * 3 + 0];
            imgData.data[i * 4 + 1] ^= diffKeystream[i * 3 + 1];
            imgData.data[i * 4 + 2] ^= diffKeystream[i * 3 + 2];
            imgData.data[i * 4 + 3] = 255; // Pinned opaque alpha
        }

        // 6. HMAC-SHA256 Tag over AAD || Pixels
        onProgress(80, 'auth', 'Computing HMAC-SHA256 integrity tag...');
        const pixelBytes = this.buildArgbPixelBytes(imgData.data, totalPixels);

        const hmacPayload = new Uint8Array(aad.length + pixelBytes.length);
        hmacPayload.set(aad, 0);
        hmacPayload.set(pixelBytes, aad.length);
        const tag = new Uint8Array(await crypto.subtle.sign('HMAC', kAuth, hmacPayload));

        // 7. Base64 Metadata Envelope (v2 = 73 bytes, v3 = 138 bytes)
        const envelopeLength = isAsymmetric ? this.ENVELOPE_V3_BYTE_LENGTH : this.ENVELOPE_V2_BYTE_LENGTH;
        const envelope = new Uint8Array(envelopeLength);
        envelope.set(aad, 0);
        envelope.set(tag, aad.length);
        const metadataBase64 = uint8ArrayToBase64(envelope);

        // 8. Render cipher image and inject fyeO chunk
        onProgress(90, 'encode', 'Packing PNG container with fyeO metadata envelope...');
        ctx.putImageData(imgData, 0, 0);
        const cipherBlob = await offscreen.convertToBlob({ type: 'image/png' });
        const cipherPngBytes = new Uint8Array(await cipherBlob.arrayBuffer());
        const finalPngBytes = PngChunkHelper.injectTextChunk(cipherPngBytes, 'fyeO', metadataBase64);

        // Wipe sensitive key bytes
        masterKey.fill(0);
        kPermBytes.fill(0);
        kDiffBytes.fill(0);
        kAuthBytes.fill(0);

        onProgress(100, 'done', 'Encryption complete!');
        return {
            blob: new Blob([finalPngBytes], { type: 'image/png' }),
            width,
            height,
            isAsymmetric
        };
    }

    /**
     * Full decryption routine executed in Web Worker.
     * Supports:
     * - Symmetric Passphrase Mode (v2): password string
     * - Asymmetric Device-to-Device Mode (v3): devicePrivateKey (CryptoKey / raw PKCS8)
     */
    static async decrypt(fileBlob, keyOrPassword, onProgress) {
        // 1. Read PNG bytes and extract fyeO chunk
        onProgress(10, 'reading', 'Parsing and inspecting PNG metadata container...');
        const fileBytes = new Uint8Array(await fileBlob.arrayBuffer());
        const metadataBase64 = PngChunkHelper.extractTextChunk(fileBytes, 'fyeO');

        if (!metadataBase64) {
            throw new FyeoError(
                'Missing or invalid authentication metadata. Ensure the image was sent as an uncompressed document.',
                'CORRUPTED_OR_COMPRESSED_IMAGE'
            );
        }

        let envelopeBytes;
        try {
            envelopeBytes = base64ToUint8Array(metadataBase64);
        } catch (e) {
            throw new FyeoError('Malformed Base64 in metadata container.', 'CORRUPTED_OR_COMPRESSED_IMAGE');
        }

        const magicStr = String.fromCharCode(...envelopeBytes.subarray(0, 4));
        if (magicStr !== 'FYEO') {
            throw new FyeoError('Unrecognized container magic header.', 'CORRUPTED_OR_COMPRESSED_IMAGE');
        }

        const version = envelopeBytes[4];
        if (version !== this.VERSION_V2 && version !== this.VERSION_V3) {
            throw new FyeoError(`Unsupported protocol version: ${version}`, 'CORRUPTED_OR_COMPRESSED_IMAGE');
        }

        const isAsymmetric = (version === this.VERSION_V3);
        const expectedEnvelopeLength = isAsymmetric ? this.ENVELOPE_V3_BYTE_LENGTH : this.ENVELOPE_V2_BYTE_LENGTH;
        if (envelopeBytes.length !== expectedEnvelopeLength) {
            throw new FyeoError('Malformed metadata container length.', 'CORRUPTED_OR_COMPRESSED_IMAGE');
        }

        const salt = envelopeBytes.subarray(5, 21);
        const nonce = envelopeBytes.subarray(21, 33);
        const envView = new DataView(envelopeBytes.buffer, envelopeBytes.byteOffset, envelopeBytes.byteLength);
        const expectedWidth = envView.getUint32(33, false);
        const expectedHeight = envView.getUint32(37, false);

        let ephPub65 = null;
        let expectedTag = null;
        let aad = null;

        if (isAsymmetric) {
            ephPub65 = envelopeBytes.subarray(41, 106);
            expectedTag = envelopeBytes.subarray(106, 138);
            aad = envelopeBytes.subarray(0, 106);
        } else {
            expectedTag = envelopeBytes.subarray(41, 73);
            aad = envelopeBytes.subarray(0, 41);
        }

        // 2. Decode cipher PNG to canvas
        let bitmap;
        try {
            bitmap = await createImageBitmap(fileBlob, { colorSpaceConversion: 'none' });
        } catch (e) {
            bitmap = await createImageBitmap(fileBlob);
        }

        if (bitmap.width !== expectedWidth || bitmap.height !== expectedHeight) {
            throw new FyeoError(
                'Image dimensions mismatch or image has been cropped.',
                'IMAGE_DIMENSIONS_MISMATCH_OR_CROPPED'
            );
        }

        const width = expectedWidth;
        const height = expectedHeight;
        const totalPixels = width * height;

        const offscreen = new OffscreenCanvas(width, height);
        const ctx = offscreen.getContext('2d', { willReadFrequently: true });
        ctx.drawImage(bitmap, 0, 0);
        const imgData = ctx.getImageData(0, 0, width, height);

        // 3. Re-derive Master & Auth Keys
        let masterKey;
        if (isAsymmetric) {
            onProgress(25, 'kdf', 'Executing ECDH point multiplication with device private key...');
            let privateKey = keyOrPassword;
            if (!(privateKey instanceof CryptoKey)) {
                if (typeof keyOrPassword === 'string' && keyOrPassword.startsWith('fyeo-priv-')) {
                    const privBytes = base64ToUint8Array(keyOrPassword.substring(10));
                    privateKey = await crypto.subtle.importKey(
                        'pkcs8',
                        privBytes,
                        { name: 'ECDH', namedCurve: 'P-256' },
                        false,
                        ['deriveBits']
                    );
                } else {
                    throw new FyeoError('This photo is locked to a recipient device key. Device private key required.', 'DEVICE_KEY_REQUIRED');
                }
            }
            masterKey = await this.deriveMasterKeyFromEcdh(privateKey, ephPub65, salt);
        } else {
            onProgress(25, 'kdf', 'Deriving cryptographic keys (PBKDF2 100,000 rounds)...');
            if (typeof keyOrPassword !== 'string' || !keyOrPassword) {
                throw new FyeoError('Passphrase required to decrypt this photo.', 'PASSWORD_REQUIRED');
            }
            masterKey = await this.deriveMasterKey(keyOrPassword, salt);
        }

        const kAuthBytes = await this.hkdfExpand(masterKey, 'FYEO-v2-Auth-HMAC', 32);
        const kAuth = await crypto.subtle.importKey('raw', kAuthBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);

        // 4. Authenticate HMAC-SHA256 Tag in Constant Time
        onProgress(45, 'auth', 'Verifying container integrity & authenticity...');
        const pixelBytes = this.buildArgbPixelBytes(imgData.data, totalPixels);

        const hmacPayload = new Uint8Array(aad.length + pixelBytes.length);
        hmacPayload.set(aad, 0);
        hmacPayload.set(pixelBytes, aad.length);
        const candidateTag = new Uint8Array(await crypto.subtle.sign('HMAC', kAuth, hmacPayload));

        if (!constantTimeEqual(expectedTag, candidateTag)) {
            masterKey.fill(0);
            kAuthBytes.fill(0);
            throw new FyeoError(
                isAsymmetric ? 'This photo was not encrypted for your device, or has been altered.' : 'Incorrect password or image pixels have been altered.',
                'AUTHENTICATION_FAILED'
            );
        }

        // 5. Invert RGB Keystream Diffusion
        onProgress(60, 'diffuse', 'Inverting RGB keystream diffusion...');
        const kDiffBytes = await this.hkdfExpand(masterKey, 'FYEO-v2-Diffusion', 32);
        const kDiff = await crypto.subtle.importKey('raw', kDiffBytes, { name: 'AES-CTR' }, false, ['encrypt']);

        const counterBlock = new Uint8Array(16);
        counterBlock.set(nonce, 0);
        const zeroPlaintext = new Uint8Array(totalPixels * 3);
        const diffKeystream = new Uint8Array(await crypto.subtle.encrypt(
            { name: 'AES-CTR', counter: counterBlock, length: 32 },
            kDiff,
            zeroPlaintext
        ));

        for (let i = 0; i < totalPixels; i++) {
            imgData.data[i * 4 + 0] ^= diffKeystream[i * 3 + 0];
            imgData.data[i * 4 + 1] ^= diffKeystream[i * 3 + 1];
            imgData.data[i * 4 + 2] ^= diffKeystream[i * 3 + 2];
            imgData.data[i * 4 + 3] = 255;
        }

        // 6. Invert Fisher-Yates Pixel Permutation
        onProgress(80, 'permute', 'Inverting Fisher-Yates pixel permutation...');
        const kPermBytes = await this.hkdfExpand(masterKey, 'FYEO-v2-Permutation', 32);
        const kPerm = await crypto.subtle.importKey('raw', kPermBytes, { name: 'AES-CTR' }, false, ['encrypt']);

        const permGen = new WebKeystreamGenerator(kPerm, nonce);
        await permGen.refillBuffer(totalPixels * 4 + 65536);
        const swapTarget = new Uint32Array(totalPixels);
        for (let i = totalPixels - 1; i > 0; i--) {
            swapTarget[i] = await permGen.nextUniformInt(i + 1);
        }

        const pixel32 = new Uint32Array(imgData.data.buffer, imgData.data.byteOffset, totalPixels);
        for (let i = 1; i < totalPixels; i++) {
            const j = swapTarget[i];
            const tmp = pixel32[i];
            pixel32[i] = pixel32[j];
            pixel32[j] = tmp;
        }

        // 7. Output restored plain image PNG
        onProgress(95, 'encode', 'Reconstructing original image...');
        ctx.putImageData(imgData, 0, 0);
        const plainBlob = await offscreen.convertToBlob({ type: 'image/png' });

        // Zero out subkeys
        masterKey.fill(0);
        kAuthBytes.fill(0);
        kDiffBytes.fill(0);
        kPermBytes.fill(0);

        onProgress(100, 'done', 'Decryption complete!');
        return {
            blob: plainBlob,
            width,
            height
        };
    }
}

// 6. Worker Event Listener Dispatcher
self.onmessage = async (e) => {
    const { type, id, fileBlob, password, recipientKey, privateKey } = e.data || {};
    if (!id) return;

    const onProgress = (percent, stage, message) => {
        self.postMessage({ type: 'PROGRESS', id, percent, stage, message });
    };

    try {
        if (type === 'ENCRYPT') {
            const keyToUse = recipientKey || password;
            const result = await VisualAeadWorkerEngine.encrypt(fileBlob, keyToUse, onProgress);
            self.postMessage({
                type: 'SUCCESS',
                id,
                action: 'encrypt',
                blob: result.blob,
                width: result.width,
                height: result.height,
                isAsymmetric: result.isAsymmetric
            });
        } else if (type === 'DECRYPT') {
            const keyToUse = privateKey || password;
            const result = await VisualAeadWorkerEngine.decrypt(fileBlob, keyToUse, onProgress);
            self.postMessage({
                type: 'SUCCESS',
                id,
                action: 'decrypt',
                blob: result.blob,
                width: result.width,
                height: result.height
            });
            // Generate persistent ECDH P-256 Keypair for this browser (extractable: false on private key)
            const keyPair = await crypto.subtle.generateKey(
                { name: 'ECDH', namedCurve: 'P-256' },
                false,
                ['deriveKey', 'deriveBits']
            );
            const pubRaw = new Uint8Array(await crypto.subtle.exportKey('raw', keyPair.publicKey));
            const pubHandle = 'fyeo-pub-' + uint8ArrayToBase64(pubRaw);

            self.postMessage({
                type: 'DEVICE_KEY_GENERATED',
                id,
                publicKey: pubHandle,
                privateKey: keyPair.privateKey
            });
        } else if (type === 'ZEROIZE') {
            // Acknowledge memory zeroization / reset
            self.postMessage({
                type: 'ZEROIZED',
                id
            });
        } else {
            throw new FyeoError(`Unknown operation type: ${type}`, 'INVALID_ACTION');
        }
    } catch (err) {
        self.postMessage({
            type: 'ERROR',
            id,
            action: type ? type.toLowerCase() : 'unknown',
            error: err.message || 'Operation failed',
            code: err.code || 'CRYPTO_ERROR'
        });
    }
};

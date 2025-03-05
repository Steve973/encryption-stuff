package org.example.pbe;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.mac.MacConfig;
import com.google.crypto.tink.subtle.AesGcmJce;
import com.google.crypto.tink.subtle.Hkdf;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Optional;

import static org.example.pbe.SecurityLevel.fromByte;

/**
 * Utility class for password-based encryption and decryption.
 * Uses Google Tink library for secure cryptographic operations.
 */
public class PasswordBasedEncryptionUtil {
    private static final SecurityLevel DEFAULT_SECURITY_LEVEL = SecurityLevel.MEDIUM;
    private static final SecureRandom secureRandom = new SecureRandom();

    // Register all AEAD implementations with Tink
    static {
        try {
            AeadConfig.register();
            MacConfig.register();
        } catch (GeneralSecurityException e) {
            throw new RuntimeException("Failed to initialize encryption library", e);
        }
    }

    /**
     * Encrypts the given plaintext using a password.
     *
     * @param plaintext     The text to encrypt
     * @param password      The password to derive encryption key from
     * @param securityLevel the security level to use
     * @return Base64-encoded encrypted data including salt and metadata
     * @throws GeneralSecurityException if encryption fails
     */
    public String encrypt(String plaintext, String password, SecurityLevel securityLevel)
            throws GeneralSecurityException {
        // Generate a random salt
        byte[] salt = new byte[securityLevel.getSaltSizeBytes()];
        secureRandom.nextBytes(salt);

        // Derive encryption key from password using HKDF with PBKDF2-like strengthening
        byte[] derivedKey = deriveKey(
                password, salt, securityLevel.getIterations(),
                "Hmac" + securityLevel.getHmacAlgorithm().getHashType().toString(),
                securityLevel.getKeySizeBytes());

        // Get an AEAD primitive using the derived key
        Aead aead = createAead(derivedKey);

        // Encrypt the plaintext
        byte[] plaintextBytes = plaintext.getBytes(StandardCharsets.UTF_8);
        byte[] encrypted = aead.encrypt(plaintextBytes, null);

        // Format: [Version(1)][SecurityLevel(1)][SaltSize(1)][Salt(variable)][Encrypted(variable)]
        byte version = 1;
        byte securityLevelByte = securityLevel.getSecurityLevelByte();

        ByteBuffer buffer = ByteBuffer.allocate(3 + salt.length + encrypted.length);
        buffer.put(version);
        buffer.put(securityLevelByte);
        buffer.put((byte) securityLevel.getSaltSizeBytes());
        buffer.put(salt);
        buffer.put(encrypted);

        // Encode as Base64 for easy storage and transmission
        return Base64.getEncoder().encodeToString(buffer.array());
    }

    /**
     * Encrypts the given plaintext using a password with default security level.
     *
     * @param plaintext The text to encrypt
     * @param password  The password to derive encryption key from
     * @return Base64-encoded encrypted data including salt and metadata
     * @throws GeneralSecurityException if encryption fails
     */
    public String encrypt(String plaintext, String password) throws GeneralSecurityException {
        if (password == null) {
            throw new NullPointerException("Password cannot be null");
        } else if (password.isEmpty()) {
            throw new IllegalArgumentException("Password cannot be empty");
        }
        return encrypt(plaintext, password, DEFAULT_SECURITY_LEVEL);
    }

    /**
     * Decrypts the given ciphertext using a password.
     *
     * @param encryptedBase64 Base64-encoded encrypted data created by encrypt()
     * @param password        The password used for encryption
     * @return The decrypted plaintext
     * @throws GeneralSecurityException if decryption fails (wrong password, corrupted data, etc.)
     */
    public String decrypt(String encryptedBase64, String password)
            throws GeneralSecurityException {
        // Decode the Base64 string
        byte[] encryptedData = Base64.getDecoder().decode(encryptedBase64);
        ByteBuffer buffer = ByteBuffer.wrap(encryptedData);

        // Read metadata
        byte version = buffer.get();
        if (version != 1) {
            throw new IllegalArgumentException("Unsupported version: " + version);
        }

        byte securityLevelByte = buffer.get();
        SecurityLevel securityLevel = fromByte(securityLevelByte);

        int saltSize = buffer.get() & 0xFF; // Convert to unsigned value
        byte[] salt = new byte[saltSize];
        buffer.get(salt);

        // Extract the actual encrypted data
        int encryptedSize = encryptedData.length - (3 + saltSize);
        byte[] encrypted = new byte[encryptedSize];
        buffer.get(encrypted);

        // Derive the key from password
        byte[] derivedKey = deriveKey(
                password, salt, securityLevel.getIterations(),
                "Hmac" + securityLevel.getHmacAlgorithm().getHashType().toString(),
                securityLevel.getKeySizeBytes());

        // Get AEAD and decrypt
        Aead aead = createAead(derivedKey);
        byte[] decrypted = aead.decrypt(encrypted, null);

        // Convert back to string
        return new String(decrypted, StandardCharsets.UTF_8);
    }

    /**
     * Derives an encryption key from a password using PBKDF2-like strengthening with HKDF.
     *
     * @param password     the password to derive the key from
     * @param salt         the salt to use for key derivation
     * @param iterations   the number of iterations for key strengthening
     * @param algorithm    the HMAC algorithm to use
     * @param keySizeBytes the desired key size in bytes
     * @return the derived key
     * @throws GeneralSecurityException if key derivation fails
     */
    private byte[] deriveKey(String password, byte[] salt, int iterations, String algorithm, int keySizeBytes)
            throws GeneralSecurityException {
        byte[] passwordBytes = password.getBytes(StandardCharsets.UTF_8);

        // Initial HKDF extraction
        byte[] key = Hkdf.computeHkdf(algorithm, passwordBytes, salt, null, keySizeBytes);

        // Additional strengthening iterations (similar to PBKDF2)
        for (int i = 1; i < iterations; i++) {
            if (i % 1000 == 0) {
                // Periodically reincorporate the salt to prevent cycles
                key = Hkdf.computeHkdf(algorithm, key, salt, null, keySizeBytes);
            } else {
                // Use a simple HMAC instead of PrfMac
                key = Hkdf.computeHkdf(algorithm, key, key, null, keySizeBytes);
            }
        }

        return key;
    }

    /**
     * Creates an AEAD primitive from a raw key.
     *
     * @param keyBytes the raw key bytes
     * @return the AEAD primitive
     */
    private Aead createAead(byte[] keyBytes) throws GeneralSecurityException {
        return new AesGcmJce(keyBytes);
    }
}
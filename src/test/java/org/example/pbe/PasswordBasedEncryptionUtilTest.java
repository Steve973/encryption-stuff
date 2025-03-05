package org.example.pbe;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import static org.junit.jupiter.api.Assertions.*;

import java.security.GeneralSecurityException;
import java.util.Base64;

public class PasswordBasedEncryptionUtilTest {

    private PasswordBasedEncryptionUtil encryptionUtil;
    private static final String TEST_PASSWORD = "TestPassword123!";
    private static final String TEST_DATA = "This is test data that needs to be encrypted";

    @BeforeEach
    public void setup() {
        encryptionUtil = new PasswordBasedEncryptionUtil();
    }

    @Test
    public void testEncryptionDecryption() throws GeneralSecurityException {
        // Encrypt with default security level
        String encrypted = encryptionUtil.encrypt(TEST_DATA, TEST_PASSWORD);
        
        // Decrypt and verify
        String decrypted = encryptionUtil.decrypt(encrypted, TEST_PASSWORD);
        
        assertEquals(TEST_DATA, decrypted, "Decrypted data should match original");
    }

    @ParameterizedTest
    @EnumSource(SecurityLevel.class)
    public void testAllSecurityLevels(SecurityLevel level) throws GeneralSecurityException {
        // Encrypt with specific security level
        String encrypted = encryptionUtil.encrypt(TEST_DATA, TEST_PASSWORD, level);
        
        // Decrypt and verify
        String decrypted = encryptionUtil.decrypt(encrypted, TEST_PASSWORD);
        
        assertEquals(TEST_DATA, decrypted, "Decrypted data should match original for level " + level);
    }

    @Test
    public void testWrongPassword() throws GeneralSecurityException {
        String encrypted = encryptionUtil.encrypt(TEST_DATA, TEST_PASSWORD);
        
        // Try to decrypt with wrong password
        Exception exception = assertThrows(GeneralSecurityException.class,
                () -> encryptionUtil.decrypt(encrypted, "WrongPassword123!"));

        assertEquals("Tag mismatch!", exception.getMessage());
    }

    @Test
    public void testEmptyData() throws GeneralSecurityException {
        String emptyData = "";
        String encrypted = encryptionUtil.encrypt(emptyData, TEST_PASSWORD);
        String decrypted = encryptionUtil.decrypt(encrypted, TEST_PASSWORD);
        
        assertEquals(emptyData, decrypted, "Empty string should encrypt and decrypt properly");
    }

    @Test
    public void testLargeData() throws GeneralSecurityException {
        // Create 1MB of test data
        StringBuilder largeData = new StringBuilder();
        largeData.append("1234567890".repeat(1024 * 1024 / 10));
        
        String encrypted = encryptionUtil.encrypt(largeData.toString(), TEST_PASSWORD);
        String decrypted = encryptionUtil.decrypt(encrypted, TEST_PASSWORD);
        
        assertEquals(largeData.toString(), decrypted, "Large data should encrypt and decrypt properly");
    }

    @ParameterizedTest
    @EnumSource(SecurityLevel.class)
    public void testPerformance(SecurityLevel level) throws GeneralSecurityException {
        // Measure encryption time
        long startEncrypt = System.nanoTime();
        String encrypted = encryptionUtil.encrypt(TEST_DATA, TEST_PASSWORD, level);
        long encryptTime = System.nanoTime() - startEncrypt;
        
        // Measure decryption time
        long startDecrypt = System.nanoTime();
        encryptionUtil.decrypt(encrypted, TEST_PASSWORD);
        long decryptTime = System.nanoTime() - startDecrypt;
        
        System.out.printf("Security Level %s - Encrypt: %.2f ms, Decrypt: %.2f ms%n", 
                level, 
                encryptTime / 1_000_000.0, 
                decryptTime / 1_000_000.0);
    }
    
    @Test
    public void testMultipleThreads() throws Exception {
        // Test concurrent encryption/decryption with multiple threads
        int threadCount = 10;
        Thread[] threads = new Thread[threadCount];
        boolean[] results = new boolean[threadCount];
        
        for (int i = 0; i < threadCount; i++) {
            final int threadIndex = i;
            threads[i] = new Thread(() -> {
                try {
                    String data = "Thread " + threadIndex + " data: " + TEST_DATA;
                    String encrypted = encryptionUtil.encrypt(data, TEST_PASSWORD);
                    String decrypted = encryptionUtil.decrypt(encrypted, TEST_PASSWORD);
                    results[threadIndex] = data.equals(decrypted);
                } catch (Exception e) {
                    fail("Exception occurred during encryption/decryption: " + e.getMessage());
                    results[threadIndex] = false;
                }
            });
            threads[i].start();
        }
        
        // Wait for all threads to complete
        for (Thread thread : threads) {
            thread.join();
        }
        
        // Verify all results
        for (int i = 0; i < threadCount; i++) {
            assertTrue(results[i], "Thread " + i + " encryption/decryption failed");
        }
    }
    
    @Test
    public void testRepeatedEncryption() throws GeneralSecurityException {
        // Test that repeated encryption of the same data produces different results (due to salt)
        String encrypted1 = encryptionUtil.encrypt(TEST_DATA, TEST_PASSWORD);
        String encrypted2 = encryptionUtil.encrypt(TEST_DATA, TEST_PASSWORD);
        
        assertNotEquals(encrypted1, encrypted2, "Repeated encryption should produce different results");
    }

    @Test
    public void testIncorrectlyFormattedInput() {
        Exception exception = assertThrows(IllegalArgumentException.class,
                () -> encryptionUtil.decrypt("not-a-valid-encrypted-string", TEST_PASSWORD));
        String exceptionMessage = exception.getMessage();
        assertTrue(exceptionMessage.contains("Illegal base64 character") || exceptionMessage.contains("Invalid"),
                "Should reject improperly formatted data");
    }

    @Test
    public void testCorruptedData() throws GeneralSecurityException {
        String encrypted = encryptionUtil.encrypt(TEST_DATA, TEST_PASSWORD);

        // Corrupt the data by changing a character in the middle
        StringBuilder corrupted = new StringBuilder(encrypted);
        int middleIndex = encrypted.length() / 2;
        char c = encrypted.charAt(middleIndex);
        corrupted.setCharAt(middleIndex, c == 'A' ? 'B' : 'A');

        Exception exception = assertThrows(GeneralSecurityException.class,
                () -> encryptionUtil.decrypt(corrupted.toString(), TEST_PASSWORD));
        String exceptionMessage = exception.getMessage();
        assertTrue(exceptionMessage.contains("Tag") || exceptionMessage.contains("integrity"),
                "Should detect data corruption");
    }

    @Test
    public void testDifferentPasswordLengths() throws GeneralSecurityException {
        String shortPassword = "short";
        String longPassword = "ThisIsAReallyLongPasswordThatSomeoneCouldPossiblyUseInARealWorld" +
                "ScenarioToProtectVeryImportantData123456789!@#$%^&*()";

        // Test with short password
        String encryptedShort = encryptionUtil.encrypt(TEST_DATA, shortPassword);
        String decryptedShort = encryptionUtil.decrypt(encryptedShort, shortPassword);
        assertEquals(TEST_DATA, decryptedShort);

        // Test with long password
        String encryptedLong = encryptionUtil.encrypt(TEST_DATA, longPassword);
        String decryptedLong = encryptionUtil.decrypt(encryptedLong, longPassword);
        assertEquals(TEST_DATA, decryptedLong);
    }

    @Test
    public void testNonLatinPasswords() throws GeneralSecurityException {
        String[] passwords = {
                "пароль",                  // Russian
                "パスワード",                  // Japanese
                "كلمة المرور",             // Arabic
                "密码",                     // Chinese
                "😀🔑🔒👍"                  // Emoji
        };

        for (String password : passwords) {
            String encrypted = encryptionUtil.encrypt(TEST_DATA, password);
            String decrypted = encryptionUtil.decrypt(encrypted, password);
            assertEquals(TEST_DATA, decrypted, "Failed with password: " + password);
        }
    }

    @Test
    public void testSecurityLevelDifferences() throws GeneralSecurityException {
        // Test different security levels produce different outputs
        String encryptedLow = encryptionUtil.encrypt(TEST_DATA, TEST_PASSWORD, SecurityLevel.LOW);
        String encryptedMedium = encryptionUtil.encrypt(TEST_DATA, TEST_PASSWORD, SecurityLevel.MEDIUM);
        String encryptedHigh = encryptionUtil.encrypt(TEST_DATA, TEST_PASSWORD, SecurityLevel.HIGH);

        assertNotEquals(encryptedLow, encryptedMedium);
        assertNotEquals(encryptedMedium, encryptedHigh);
        assertNotEquals(encryptedLow, encryptedHigh);

        // Test we can correctly decrypt from different security levels
        assertEquals(TEST_DATA, encryptionUtil.decrypt(encryptedLow, TEST_PASSWORD));
        assertEquals(TEST_DATA, encryptionUtil.decrypt(encryptedMedium, TEST_PASSWORD));
        assertEquals(TEST_DATA, encryptionUtil.decrypt(encryptedHigh, TEST_PASSWORD));
    }

    @Test
    public void testBinaryData() throws GeneralSecurityException {
        // Create binary data with all possible byte values
        byte[] binaryData = new byte[256];
        for (int i = 0; i < 256; i++) {
            binaryData[i] = (byte) i;
        }

        String binaryString = Base64.getEncoder().encodeToString(binaryData);

        String encrypted = encryptionUtil.encrypt(binaryString, TEST_PASSWORD);
        String decrypted = encryptionUtil.decrypt(encrypted, TEST_PASSWORD);

        assertEquals(binaryString, decrypted, "Binary data should encrypt and decrypt correctly");
    }

    @Test
    public void testVersionCompatibility() throws GeneralSecurityException {
        String encrypted = encryptionUtil.encrypt(TEST_DATA, TEST_PASSWORD);

        // Simulate altering the version byte to an unsupported version
        byte[] decodedBytes = Base64.getDecoder().decode(encrypted);
        decodedBytes[0] = 99; // Some future version number
        String modifiedEncrypted = Base64.getEncoder().encodeToString(decodedBytes);

        Exception exception = assertThrows(IllegalArgumentException.class,
                () -> encryptionUtil.decrypt(modifiedEncrypted, TEST_PASSWORD));

        assertTrue(exception.getMessage().contains("version"),
                "Should reject unsupported versions");
    }

    @Test
    public void testNullAndEmptyInputs() {
        // Test with empty password
        assertThrows(IllegalArgumentException.class,
                () -> encryptionUtil.encrypt(TEST_DATA, ""));

        // Test with null password
        assertThrows(NullPointerException.class,
                () -> encryptionUtil.encrypt(TEST_DATA, null));

        // Test with null plaintext
        assertThrows(NullPointerException.class,
                () -> encryptionUtil.encrypt(null, TEST_PASSWORD));
    }
}
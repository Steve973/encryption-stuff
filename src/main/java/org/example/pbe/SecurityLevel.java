package org.example.pbe;

import com.google.crypto.tink.mac.HmacParameters;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

import static com.google.crypto.tink.mac.PredefinedMacParameters.*;

/**
 * Enum representing available security levels for password-based encryption.
 */
@Getter
@RequiredArgsConstructor
public enum SecurityLevel {
    LOW(10_000, 16, 32, (byte) 1, HMAC_SHA256_128BITTAG),
    MEDIUM(50_000, 16, 32, (byte) 2, HMAC_SHA256_256BITTAG),
    HIGH(100_000, 16, 32, (byte) 3, HMAC_SHA512_256BITTAG);
    
    private final int iterations;
    private final int saltSizeBytes;
    private final int keySizeBytes;
    private final byte securityLevelByte;
    private final HmacParameters hmacAlgorithm;

    public static SecurityLevel fromByte(byte b) {
        for (SecurityLevel level : values()) {
            if (level.securityLevelByte == b) {
                return level;
            }
        }
        throw new IllegalArgumentException("Invalid security level byte: " + b);
    }
}
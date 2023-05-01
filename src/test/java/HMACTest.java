import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

class HMACTest {
    @Test
    public void testComputeHMAC() throws NoSuchAlgorithmException {

        // Input data
        byte[] message = "test message".getBytes();
        byte[] key = "secret key".getBytes();
        int blocksize = 64;
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");

        // Expected output
        byte[] expectedHMAC = new byte[] {
                (byte) -92, (byte) 102, (byte) -89, (byte) 89, (byte) 98, (byte) -95,
                (byte) 24, (byte) 110, (byte) -34, (byte) -102, (byte) 72, (byte) -21,
                (byte) -50, (byte) -17, (byte) 39, (byte) 116, (byte) 47, (byte) 64, (byte) 2,
                (byte) -99, (byte) 66, (byte) -85, (byte) -83, (byte) 84, (byte) 25, (byte) -79,
                (byte) 88, (byte) -70, (byte) 95, (byte) -76,(byte) 84, (byte) -97
        };

        // Compute HMAC and compare with expected output
        byte[] actualHMAC = HMAC.computeHMAC(message, key, blocksize, messageDigest);
        Assertions.assertTrue(Arrays.equals(expectedHMAC, actualHMAC));
    }
}
import org.junit.jupiter.api.Test;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import static org.junit.jupiter.api.Assertions.*;

public class HMACTest {

    @Test
    public void testComputeHMAC() throws NoSuchAlgorithmException {
        byte[] message = "Hello World".getBytes();
        byte[] key = "secret".getBytes();
        int blocksize = 64;
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        byte[] expected = new byte[]{66, -102, 32, -74, -101, -80, 11, 7, 31, 96, 38, 58, 46, 56, 87, -124, -45, 22, 1, -118, -31, -63, 45, -116, -73, 75, 87, 58, -66, -29, 2, 28};
        byte[] result = HMAC.computeHMAC(message, key, blocksize, messageDigest);
        assertArrayEquals(expected, result);
    }



}


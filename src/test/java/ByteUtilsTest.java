import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class ByteUtilsTest {
    @Test
    public void testGeneratePad() {
        byte[] expected = {1, 1, 1, 1};
        byte[] result = ByteUtils.generatePad(1, 4);
        assertArrayEquals(expected, result);
    }

    @Test
    public void testComputeXor() {
        byte[] a = {1, 2, 3, 4};
        byte[] b = {2, 3, 4, 5};
        byte[] expected = {3, 1, 7, 1};
        byte[] result = ByteUtils.computeXor(a, b);
        assertArrayEquals(expected, result);
    }

    @Test
    public void testConcatByteArrays() {
        byte[] a = {1, 2, 3};
        byte[] b = {4, 5, 6};
        byte[] expected = {1, 2, 3, 4, 5, 6};
        byte[] result = ByteUtils.concatByteArrays(a, b);
        assertArrayEquals(expected, result);
    }
}
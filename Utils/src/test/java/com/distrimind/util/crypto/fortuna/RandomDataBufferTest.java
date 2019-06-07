package com.distrimind.util.crypto.fortuna;


import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import static org.testng.Assert.assertEquals;


public class RandomDataBufferTest {

    private RandomDataBuffer randomDataBuffer;
    private Supplier<byte[]> dataSupplier;

    @BeforeMethod
    public void setUp() {
        randomDataBuffer = new RandomDataBuffer();
        dataSupplier = new Supplier<byte[]>() {
            @Override
            public byte[] get() {
                return new byte[]{(byte) 0xde, (byte) 0xad, (byte) 0xbe, (byte) 0xef, (byte) 0xfa, (byte) 0xce, (byte) 0xfe, (byte) 0xed};
            }
        };
    }

    @Test
    public void testGettingBits() {
        assertEquals("deadbeef", Integer.toHexString(randomDataBuffer.next(32, dataSupplier)));
        assertEquals("f", Integer.toHexString(randomDataBuffer.next(4, dataSupplier)));
        assertEquals("ac", Integer.toHexString(randomDataBuffer.next(8, dataSupplier)));
        assertEquals("efee", Integer.toHexString(randomDataBuffer.next(16, dataSupplier)));
        assertEquals("ddeadbee", Integer.toHexString(randomDataBuffer.next(32, dataSupplier)));
        assertEquals("f", Integer.toHexString(randomDataBuffer.next(4, dataSupplier)));

        for (int i = 0; i < 32; i++) {
            assertEquals("" + Integer.toBinaryString(0xfacefeed).charAt(i), Integer.toBinaryString(randomDataBuffer.next(1, dataSupplier)));
        }
        for (int i = 0; i < 32; i++) {
            assertEquals("" + Integer.toBinaryString(0xdeadbeef).charAt(i), Integer.toBinaryString(randomDataBuffer.next(1, dataSupplier)));
        }
    }

    @Test(expectedExceptions = IllegalStateException.class)
    public void shouldFailIfNoDataIsProvided() {
        randomDataBuffer.next(1, new Supplier<byte[]>() {
            @Override
            public byte[] get() {
                return new byte[0];
            }
        });
    }
}

package com.distrimind.util.crypto.fortuna;

import org.testng.annotations.BeforeTest;
import org.testng.annotations.Test;
import static org.testng.Assert.*;

import java.security.MessageDigest;


public class PoolTest {
    private Pool pool;

    @BeforeTest
    public void before() {
        pool = new Pool();
    }

    @Test
    public void shouldCalculateSizeOfPool() {
        assertEquals(0, pool.size());
        pool.add(255, "Hello".getBytes());
        assertEquals(7, pool.size());
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void shouldFailIfSourceIsLessThanZero() {
        pool.add(-1, "Hello".getBytes());
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void shouldFailIfSourceIsGreaterThan255() {
        pool.add(256, "Hello".getBytes());
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void shouldFailIfEventIsEmpty() {
        pool.add(0, new byte[0]);
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void shouldFailIfEventLengthIsGreaterThan32() {
        pool.add(0, new byte[33]);
    }

    @Test
    public void shouldClearPoolAfterGetting() throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] bytes = new byte[34];
        bytes[0] = (byte) 123;
        bytes[1] = (byte) 32;

        pool.add(123, new byte[32]);
        assertEquals(34, pool.size());
        assertEquals(digest.digest(bytes), pool.getAndClear());
        assertEquals(0, pool.size());

        pool.add(123, new byte[32]);
        assertEquals(34, pool.size());
        assertEquals(digest.digest(bytes), pool.getAndClear());
        assertEquals(0, pool.size());
    }

    @Test
    public void shouldGet32BytesOfSeedData() {
        byte[] bytes = pool.getAndClear();
        assertEquals(32, bytes.length);
    }
}

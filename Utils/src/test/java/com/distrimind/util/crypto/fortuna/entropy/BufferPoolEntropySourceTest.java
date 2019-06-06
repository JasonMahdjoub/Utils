package com.distrimind.util.crypto.fortuna.entropy;

import com.distrimind.util.crypto.fortuna.accumulator.EventAdder;
import org.testng.Assert;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.Test;

import java.nio.ByteBuffer;

public class BufferPoolEntropySourceTest {

    private BufferPoolEntropySource target;
    private int adds;

    @BeforeTest
    public void before() {
        target = new BufferPoolEntropySource();
        adds = 0;
        ByteBuffer.allocateDirect(300);
    }

    @Test
    public void shouldGetBufferPoolData() {
        target.event(new EventAdder() {
            @Override
            public void add(byte[] event) {
                Assert.assertEquals(2, event.length);
                adds++;
            }
        });
        Assert.assertEquals(1, adds);
    }


}

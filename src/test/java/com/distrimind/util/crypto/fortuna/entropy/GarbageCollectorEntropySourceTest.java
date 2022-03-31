package com.distrimind.util.crypto.fortuna.entropy;

import com.distrimind.util.crypto.fortuna.accumulator.EventAdder;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

public class GarbageCollectorEntropySourceTest {

    private GarbageCollectorEntropySource target;
    private int adds;

    @BeforeMethod
    public void before() {
        target = new GarbageCollectorEntropySource();
        adds = 0;
    }

    @Test
    public void shouldGetGarbageCollectionData() {
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

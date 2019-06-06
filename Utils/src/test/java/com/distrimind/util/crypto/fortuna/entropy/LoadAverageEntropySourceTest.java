package com.distrimind.util.crypto.fortuna.entropy;

import com.distrimind.util.crypto.fortuna.accumulator.EventAdder;
import org.testng.Assert;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.Test;

public class LoadAverageEntropySourceTest {

    private LoadAverageEntropySource target;
    private int adds;

    @BeforeTest
    public void before() {
        target = new LoadAverageEntropySource();
        adds = 0;
    }

    @Test
    public void shouldAddTwoBytesAndSchedule() {
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

package com.distrimind.util.crypto.fortuna.entropy;

import com.distrimind.util.crypto.fortuna.Util;
import com.distrimind.util.crypto.fortuna.accumulator.EntropySource;
import com.distrimind.util.crypto.fortuna.accumulator.EventAdder;
import com.distrimind.util.crypto.fortuna.accumulator.EventScheduler;

import java.util.concurrent.TimeUnit;

public class FreeMemoryEntropySource implements EntropySource {
    @Override
    public void schedule(EventScheduler scheduler) {
        scheduler.schedule(100, TimeUnit.MILLISECONDS);
    }

    @Override
    public void event(EventAdder adder) {
        long freeMemory = Runtime.getRuntime().freeMemory();
        adder.add(Util.twoLeastSignificantBytes(freeMemory));
    }
}

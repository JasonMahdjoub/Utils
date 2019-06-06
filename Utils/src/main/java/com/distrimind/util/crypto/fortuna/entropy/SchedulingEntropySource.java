package com.distrimind.util.crypto.fortuna.entropy;

import com.distrimind.util.crypto.fortuna.Util;
import com.distrimind.util.crypto.fortuna.accumulator.EntropySource;
import com.distrimind.util.crypto.fortuna.accumulator.EventAdder;
import com.distrimind.util.crypto.fortuna.accumulator.EventScheduler;

import java.util.concurrent.TimeUnit;

public class SchedulingEntropySource implements EntropySource {
    private long lastTime = 0;

    @Override
    public void schedule(EventScheduler scheduler) {
        scheduler.schedule(10, TimeUnit.MILLISECONDS);
    }

    @Override
    public void event(EventAdder adder) {
        long now = System.nanoTime();
        long elapsed = now - lastTime;
        lastTime = now;
        adder.add(Util.twoLeastSignificantBytes(elapsed));
    }
}

package com.distrimind.util.crypto.fortuna.entropy;

import com.distrimind.util.crypto.fortuna.Util;
import com.distrimind.util.crypto.fortuna.accumulator.EntropySource;
import com.distrimind.util.crypto.fortuna.accumulator.EventAdder;
import com.distrimind.util.crypto.fortuna.accumulator.EventScheduler;

import java.lang.management.ManagementFactory;
import java.lang.management.ThreadMXBean;
import java.util.concurrent.TimeUnit;

public class ThreadTimeEntropySource implements EntropySource {

    private final ThreadMXBean threadMXBean = ManagementFactory.getThreadMXBean();

    @Override
    public void schedule(EventScheduler scheduler) {
        scheduler.schedule(100, TimeUnit.MILLISECONDS);
    }

    @Override
    public void event(EventAdder adder) {
        long threadTime = threadMXBean.getCurrentThreadCpuTime() + threadMXBean.getCurrentThreadUserTime();
        adder.add(Util.twoLeastSignificantBytes(threadTime));
    }
}

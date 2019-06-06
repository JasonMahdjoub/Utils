package com.distrimind.util.crypto.fortuna.entropy;

import com.distrimind.util.crypto.fortuna.Util;
import com.distrimind.util.crypto.fortuna.accumulator.EntropySource;
import com.distrimind.util.crypto.fortuna.accumulator.EventAdder;
import com.distrimind.util.crypto.fortuna.accumulator.EventScheduler;

import java.lang.management.ManagementFactory;
import java.lang.management.RuntimeMXBean;
import java.util.concurrent.TimeUnit;

public class UptimeEntropySource implements EntropySource {
    private final RuntimeMXBean runtimeMXBean = ManagementFactory.getRuntimeMXBean();

    @Override
    public void schedule(EventScheduler scheduler) {
        scheduler.schedule(1, TimeUnit.SECONDS);
    }

    @Override
    public void event(EventAdder adder) {
        long uptime = runtimeMXBean.getUptime();
        adder.add(Util.twoLeastSignificantBytes(uptime));
    }
}

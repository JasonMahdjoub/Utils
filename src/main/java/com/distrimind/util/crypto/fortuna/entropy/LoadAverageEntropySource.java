package com.distrimind.util.crypto.fortuna.entropy;

import com.distrimind.util.crypto.fortuna.Util;
import com.distrimind.util.crypto.fortuna.accumulator.EntropySource;
import com.distrimind.util.crypto.fortuna.accumulator.EventAdder;
import com.distrimind.util.crypto.fortuna.accumulator.EventScheduler;
import java.lang.management.ManagementFactory;
import java.lang.management.OperatingSystemMXBean;
import java.math.BigDecimal;
import java.util.concurrent.TimeUnit;

public class LoadAverageEntropySource implements EntropySource {

    private final OperatingSystemMXBean operatingSystemMXBean = ManagementFactory.getOperatingSystemMXBean();

    @Override
    public void schedule(EventScheduler scheduler) {
        scheduler.schedule(1, TimeUnit.SECONDS);
    }

    @Override
    public void event(EventAdder adder) {
        double systemLoadAverage = operatingSystemMXBean.getSystemLoadAverage();
        BigDecimal value = BigDecimal.valueOf(systemLoadAverage);
        long convertedValue = value.movePointRight(value.scale()).longValue();
        adder.add(Util.twoLeastSignificantBytes(convertedValue));
    }
}

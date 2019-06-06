package com.distrimind.util.crypto.fortuna.entropy;

import com.distrimind.util.crypto.fortuna.Util;
import com.distrimind.util.crypto.fortuna.accumulator.EntropySource;
import com.distrimind.util.crypto.fortuna.accumulator.EventAdder;
import com.distrimind.util.crypto.fortuna.accumulator.EventScheduler;

import java.lang.management.GarbageCollectorMXBean;
import java.lang.management.ManagementFactory;
import java.util.List;
import java.util.concurrent.TimeUnit;

public class GarbageCollectorEntropySource implements EntropySource {
    private final List<GarbageCollectorMXBean> garbageCollectorMXBeans = ManagementFactory.getGarbageCollectorMXBeans();

    @Override
    public void schedule(EventScheduler scheduler) {
        scheduler.schedule(10, TimeUnit.SECONDS);
    }

    @Override
    public void event(EventAdder adder) {
        long sum = 0;
        for (GarbageCollectorMXBean garbageCollectorMXBean : garbageCollectorMXBeans) {
            sum += garbageCollectorMXBean.getCollectionCount() + garbageCollectorMXBean.getCollectionTime();
        }
        adder.add(Util.twoLeastSignificantBytes(sum));
    }
}

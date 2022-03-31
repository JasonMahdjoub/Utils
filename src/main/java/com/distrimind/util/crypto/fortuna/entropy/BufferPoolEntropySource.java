package com.distrimind.util.crypto.fortuna.entropy;

import com.distrimind.util.crypto.fortuna.Util;
import com.distrimind.util.crypto.fortuna.accumulator.EntropySource;
import com.distrimind.util.crypto.fortuna.accumulator.EventAdder;
import com.distrimind.util.crypto.fortuna.accumulator.EventScheduler;

import java.lang.management.BufferPoolMXBean;
import java.lang.management.ManagementFactory;
import java.util.List;
import java.util.concurrent.TimeUnit;

public class BufferPoolEntropySource implements EntropySource {

    @Override
    public void schedule(EventScheduler scheduler) {
        scheduler.schedule(5, TimeUnit.SECONDS);
    }

    @Override
    public void event(EventAdder adder) {
        long sum = 0;
        List<BufferPoolMXBean> bufferPoolMXBeans = ManagementFactory.getPlatformMXBeans(BufferPoolMXBean.class);
        for (BufferPoolMXBean bufferPoolMXBean : bufferPoolMXBeans) {
            sum += bufferPoolMXBean.getMemoryUsed();
        }
        adder.add(Util.twoLeastSignificantBytes(sum));
    }
}

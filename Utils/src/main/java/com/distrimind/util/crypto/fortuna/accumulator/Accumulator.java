package com.distrimind.util.crypto.fortuna.accumulator;

import com.distrimind.util.crypto.fortuna.Pool;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

public class Accumulator {
    private final AtomicInteger sourceCount = new AtomicInteger(0);
    private final List<ScheduledFuture<?>> entropyFutures = new ArrayList<>();
    private final Pool[] pools;
    private final ScheduledExecutorService scheduler;

    public Accumulator(Pool[] pools, ScheduledExecutorService scheduler) {
        this.pools = pools;
        this.scheduler = scheduler;
    }

    public Pool[] getPools() {
        return pools;
    }

    public void addSource(final EntropySource entropySource) {
        int sourceId = sourceCount.getAndIncrement();
        final EventAdder eventAdder = new EventAdderImpl(sourceId, pools);
        final AtomicBoolean scheduled = new AtomicBoolean();
        entropySource.schedule((new EventScheduler() {
            @Override
            public void schedule(long delay, TimeUnit timeUnit) {

                entropyFutures.add(scheduler.scheduleWithFixedDelay(new Runnable() {
                    @Override
                    public void run() {
                        entropySource.event(eventAdder);
                    }
                }, 0, delay, timeUnit));
                scheduled.set(true);
            }
        }));
        if (!scheduled.get()) {
            throw new IllegalStateException("Entropy source " + entropySource.getClass().getName() + " was not scheduled to run");
        }
    }

    public void shutdownSources() {
        for (ScheduledFuture<?> s : entropyFutures)
        {
            s.cancel(false);
        }
        entropyFutures.clear();
    }
}

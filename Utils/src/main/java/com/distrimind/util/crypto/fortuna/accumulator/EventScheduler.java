package com.distrimind.util.crypto.fortuna.accumulator;

import java.util.concurrent.TimeUnit;

public interface EventScheduler {
    void schedule(long delay, TimeUnit timeUnit);
}

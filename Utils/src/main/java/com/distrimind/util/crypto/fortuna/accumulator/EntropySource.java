package com.distrimind.util.crypto.fortuna.accumulator;

public interface EntropySource {
    void schedule(EventScheduler scheduler);

    void event(EventAdder adder);
}

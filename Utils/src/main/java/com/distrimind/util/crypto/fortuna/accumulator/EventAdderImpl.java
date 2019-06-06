package com.distrimind.util.crypto.fortuna.accumulator;

import com.distrimind.util.crypto.fortuna.Pool;

class EventAdderImpl implements EventAdder {
    private int pool;
    private final int sourceId;
    private final Pool[] pools;

    EventAdderImpl(int sourceId, Pool[] pools) {
        this.sourceId = sourceId;
        this.pools = pools;
        pool = 0;
    }

    @Override
    public void add(byte[] event) {
        pool = (pool + 1) % pools.length;
        pools[pool].add(sourceId, event);
    }
}

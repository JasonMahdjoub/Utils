package com.distrimind.util.crypto.fortuna;

import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicReference;

class PrefetchingSupplier<T> implements Supplier<T> {
    private final Callable<T> delegate;
    private final ExecutorService executorService;
    private final AtomicReference<Future<T>> value = new AtomicReference<>();

    PrefetchingSupplier(Callable<T> delegate, ExecutorService executorService) {
        this.delegate = delegate;
        this.executorService = executorService;
        value.set(executorService.submit(delegate));
    }

    public synchronized T get() {
        try {
            T delegateValue = this.value.get().get();
            value.set(executorService.submit(delegate));
            return delegateValue;
        } catch (InterruptedException e) {
            throw new IllegalStateException("Interrupted while waiting for prefetch result", e);
        } catch (ExecutionException e) {
            throw new IllegalStateException("Failure while prefetching", e.getCause());
        }
    }

    void shutdownPrefetch() {
        value.getAndSet(null).cancel(true);
    }
}

package com.distrimind.util.crypto.fortuna;


import com.distrimind.util.crypto.AbstractSecureRandom;
import com.distrimind.util.crypto.SecureRandomType;
import com.distrimind.util.crypto.fortuna.accumulator.Accumulator;
import com.distrimind.util.crypto.fortuna.entropy.*;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Arrays;
import java.util.Random;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicReference;

public class Fortuna extends Random {
    private static final int MIN_POOL_SIZE = 64;
    private static final int[] POWERS_OF_TWO = initializePowersOfTwo();
    private static final int RANDOM_DATA_CHUNK_SIZE = 128 * 1024;

    private static int[] initializePowersOfTwo() {
        int[] result = new int[32];
        for (int power = 0; power < result.length; power++) {
            result[power] = (int) StrictMath.pow(2, power);
        }
        return result;
    }

    private long lastReseedTime = 0;
    private long reseedCount = 0;
    private final RandomDataBuffer randomDataBuffer;
    private final Generator generator;
    private final Accumulator accumulator;
    private final ScheduledExecutorService scheduler;
    private boolean createdScheduler;
    private final PrefetchingSupplier<byte[]> randomDataPrefetcher;
    final SecureRandomSource secureRandomSource;



    private static ScheduledExecutorService defaultScheduledExecutorService=null;
    private static ScheduledExecutorService createDefaultScheduler() {
        synchronized (Fortuna.class) {
            if (defaultScheduledExecutorService==null) {
                return defaultScheduledExecutorService = Executors.newSingleThreadScheduledExecutor(new ThreadFactory() {
                    private final ThreadFactory delegate = Executors.defaultThreadFactory();

                    @Override
                    public Thread newThread(Runnable r) {
                        Thread thread = delegate.newThread(r);
                        thread.setDaemon(true);
                        return thread;
                    }
                });
            }
            return defaultScheduledExecutorService;
        }
    }

    public void addSecureRandomSource(AbstractSecureRandom secureRandom)
    {
        secureRandomSource.add(secureRandom);
    }

    public void addSecureRandomSource(SecureRandomType secureRandomType) throws NoSuchProviderException, NoSuchAlgorithmException {
        secureRandomSource.add(secureRandomType);
    }


    public static void setDefaultScheduledExecutorService(ScheduledExecutorService defaultScheduledExecutorService) {
        Fortuna.defaultScheduledExecutorService = defaultScheduledExecutorService;
    }

    public static Fortuna createInstance() {
        return new Fortuna();
    }

    @SuppressWarnings("WeakerAccess")
    public static Fortuna createInstance(ScheduledExecutorService scheduler) {
        return new Fortuna(scheduler);
    }

    public Fortuna()  {
        this(createDefaultScheduler());
        this.createdScheduler = true;
    }

    public Fortuna(ScheduledExecutorService scheduler) {
        this.createdScheduler = false;
        this.generator = new Generator();
        this.randomDataBuffer = new RandomDataBuffer();
        AtomicReference<SecureRandomSource> secureRandomSource=new AtomicReference<>();
        this.accumulator = createAccumulator(scheduler, secureRandomSource);
        this.secureRandomSource=secureRandomSource.get();
        this.randomDataPrefetcher = new PrefetchingSupplier<>(new Callable<byte[]>() {
            @Override
            public byte[] call() {
                return Fortuna.this.randomData();
            }

        }, scheduler);
        this.scheduler = scheduler;
    }

    private static Accumulator createAccumulator(ScheduledExecutorService scheduler, AtomicReference<SecureRandomSource> secureRandomSource) {
        Pool[] pools = new Pool[32];
        for (int pool = 0; pool < pools.length; pool++) {
            pools[pool] = new Pool();
        }
        Accumulator accumulator = new Accumulator(pools, scheduler);
        accumulator.addSource(new SchedulingEntropySource());
        accumulator.addSource(new GarbageCollectorEntropySource());
        accumulator.addSource(new LoadAverageEntropySource());
        accumulator.addSource(new FreeMemoryEntropySource());
        accumulator.addSource(new ThreadTimeEntropySource());
        accumulator.addSource(new UptimeEntropySource());
        accumulator.addSource(new BufferPoolEntropySource());
        accumulator.addSource(new MemoryPoolEntropySource());
        secureRandomSource.set(new SecureRandomSource());
        accumulator.addSource(secureRandomSource.get());
        if (Files.exists(Paths.get("/dev/urandom"))) {
            accumulator.addSource(new URandomEntropySource());
        }
        while (pools[0].size() < MIN_POOL_SIZE) {
            try {
                Thread.sleep(10);
            } catch (InterruptedException e) {
                throw new Error("Interrupted while waiting for initialization", e);
            }
        }
        return accumulator;
    }

    private byte[] randomData() {
        long now = System.currentTimeMillis();
        Pool[] pools = accumulator.getPools();
        if (pools[0].size() >= MIN_POOL_SIZE && now - lastReseedTime > 100) {
            lastReseedTime = now;
            reseedCount++;
            byte[] seed = new byte[pools.length * 32]; // Maximum potential length
            int seedLength = 0;
            for (int pool = 0; pool < pools.length; pool++) {
                if (reseedCount % POWERS_OF_TWO[pool] == 0) {
                    System.arraycopy(pools[pool].getAndClear(), 0, seed, seedLength, 32);
                    seedLength += 32;
                }
            }
            generator.reseed(Arrays.copyOf(seed, seedLength));
        }
        if (reseedCount == 0) {
            throw new IllegalStateException("Generator not reseeded yet");
        } else {
            return generator.pseudoRandomData(RANDOM_DATA_CHUNK_SIZE);
        }
    }

    @Override
    protected int next(int bits) {
        secureRandomSource.setUpdate(true);
        return randomDataBuffer.next(bits, randomDataPrefetcher);
    }

    @Override
    public synchronized void setSeed(long seed) {
        // Does not do anything
    }

    @SuppressWarnings("WeakerAccess")
    public void shutdown(long timeout, TimeUnit unit) throws InterruptedException {
        randomDataPrefetcher.shutdownPrefetch();
        accumulator.shutdownSources();
        if (createdScheduler) {
            scheduler.shutdown();

            if (!scheduler.awaitTermination(timeout, unit)) {
                scheduler.shutdownNow();
            }
        }
    }

    public void shutdown() throws InterruptedException {
        shutdown(30, TimeUnit.SECONDS);
    }
}

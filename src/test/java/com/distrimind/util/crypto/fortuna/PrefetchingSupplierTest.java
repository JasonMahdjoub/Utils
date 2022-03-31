package com.distrimind.util.crypto.fortuna;

import org.testng.annotations.AfterTest;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import static org.testng.Assert.assertEquals;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;


public class PrefetchingSupplierTest {
    private ExecutorService executorService;
    private List<Integer> sleeps;

    @BeforeMethod
    public void setUp() {
        sleeps = new ArrayList<>(Arrays.asList(200, 150, 100, 50, 0));
        executorService = Executors.newFixedThreadPool(5);
    }

    @AfterTest
    public void tearDown() {
        if (executorService!=null)
            executorService.shutdown();
    }

    @Test
    public void shouldGetValues() {
        final AtomicInteger number = new AtomicInteger();
        PrefetchingSupplier<String> prefetcher = new PrefetchingSupplier<>(new Callable<String>() {
            @Override
            public String call() {
                return "hello " + number.getAndIncrement();
            }
        }, executorService);
        assertEquals("hello 0", prefetcher.get());
        assertEquals("hello 1", prefetcher.get());
        assertEquals("hello 2", prefetcher.get());
    }

    @Test
    public void shouldBeOrderedAndCorrectNumberOfOutputs() throws ExecutionException, InterruptedException {
        final AtomicInteger number = new AtomicInteger();
        final PrefetchingSupplier<Integer> prefetcher = new PrefetchingSupplier<>(new Callable<Integer>() {
            @Override
            public Integer call() {
                PrefetchingSupplierTest.this.sleep();
                return number.getAndIncrement();
            }
        }, executorService);
        final List<Integer> values = new ArrayList<>();
        List<Future<?>> futures = new ArrayList<>();
        for (int i = 0; i < 5; i++) {
            futures.add(executorService.submit(new Runnable() {
                @Override
                public void run() {
                    values.add(prefetcher.get());
                }
            }));
        }
        for (Future<?> future : futures) {
            future.get();
        }
        assertEquals(Arrays.asList(0, 1, 2, 3, 4), values);
    }

    private void sleep() {
        try {
            Thread.sleep(sleeps.remove(0));
        } catch (InterruptedException e) {
            throw new Error(e);
        }
    }
}

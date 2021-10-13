/*
Copyright or © or Copr. Jason Mahdjoub (04/02/2016)

jason.mahdjoub@distri-mind.fr

This software (Utils) is a computer program whose purpose is to give several kind of tools for developers
(ciphers, XML readers, decentralized id generators, etc.).

This software is governed by the CeCILL-C license under French law and
abiding by the rules of distribution of free software.  You can  use,
modify and/ or redistribute the software under the terms of the CeCILL-C
license as circulated by CEA, CNRS and INRIA at the following URL
"http://www.cecill.info".

As a counterpart to the access to the source code and  rights to copy,
modify and redistribute granted by the license, users are provided only
with a limited warranty  and the software's author,  the holder of the
economic rights,  and the successive licensors  have only  limited
liability.

In this respect, the user's attention is drawn to the risks associated
with loading,  using,  modifying and/or developing or reproducing the
software by the user in light of its specific status of free software,
that may mean  that it is complicated to manipulate,  and  that  also
therefore means  that it is reserved for developers  and  experienced
professionals having in-depth computer knowledge. Users are therefore
encouraged to load and test the software's suitability as regards their
requirements in conditions enabling the security of their systems and/or
data to be ensured and,  more generally, to use and operate it in the
same conditions as regards security.

The fact that you are presently reading this means that you have had
knowledge of the CeCILL-C license and that you accept its terms.
 */

package com.distrimind.util.concurrent;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.TreeSet;
import java.util.concurrent.*;

/**
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 4.8.0
 */
@SuppressWarnings("NullableProblems")
public class ScheduledPoolExecutor extends PoolExecutor implements ScheduledExecutorService {
	private final TreeSet<SF<?>> scheduledFutures=new TreeSet<>();
	private boolean pull=false;
	private long timeOfFirstOccurrenceInNanos =Long.MAX_VALUE;

	public ScheduledPoolExecutor(int minimumPoolSize, int maximumPoolSize, long keepAliveTime, TimeUnit unit) {
		super(minimumPoolSize, maximumPoolSize, keepAliveTime, unit);
	}

	public ScheduledPoolExecutor(int minimumPoolSize, int maximumPoolSize, long keepAliveTime, TimeUnit unit, ThreadFactory threadFactory) {
		super(minimumPoolSize, maximumPoolSize, keepAliveTime, unit, threadFactory);
	}

	public ScheduledPoolExecutor(int minimumPoolSize, int maximumPoolSize, long keepAliveTime, TimeUnit unit, HandlerForFailedExecution handler) {
		super(minimumPoolSize, maximumPoolSize, keepAliveTime, unit, handler);
	}

	public ScheduledPoolExecutor(int minimumPoolSize, int maximumPoolSize, long keepAliveTime, TimeUnit unit, ThreadFactory threadFactory, HandlerForFailedExecution handler) {
		super(minimumPoolSize, maximumPoolSize, keepAliveTime, unit, threadFactory, handler);
	}

	public ScheduledPoolExecutor(int minimumPoolSize, int maximumPoolSize, long keepAliveTime, TimeUnit unit, int queueBaseSize) {
		super(minimumPoolSize, maximumPoolSize, keepAliveTime, unit, queueBaseSize);
	}

	public ScheduledPoolExecutor(int minimumPoolSize, int maximumPoolSize, long keepAliveTime, TimeUnit unit, int queueBaseSize, ThreadFactory threadFactory) {
		super(minimumPoolSize, maximumPoolSize, keepAliveTime, unit, queueBaseSize, threadFactory);
	}

	public ScheduledPoolExecutor(int minimumPoolSize, int maximumPoolSize, long keepAliveTime, TimeUnit unit, int queueBaseSize, HandlerForFailedExecution handler) {
		super(minimumPoolSize, maximumPoolSize, keepAliveTime, unit, queueBaseSize, handler);
	}

	public ScheduledPoolExecutor(int minimumPoolSize, int maximumPoolSize, long keepAliveTime, TimeUnit unit, int queueBaseSize, ThreadFactory threadFactory, HandlerForFailedExecution handler) {
		super(minimumPoolSize, maximumPoolSize, keepAliveTime, unit, queueBaseSize, threadFactory, handler);
	}

	@SuppressWarnings("NullableProblems")
	private class SF<T> extends PoolExecutor.Future<T> implements ScheduledFuture<T>
	{
		long start;
		public SF(Callable<T> callable, long initialDelay, TimeUnit unit) {
			super(callable);
			start=System.nanoTime()+unit.toNanos(initialDelay);
		}
		/*public SF(SF<T> o, long start) {
			super(o);
			this.start=start;
		}*/

		@Override
		public long getDelay(TimeUnit unit) {
			return TimeUnit.NANOSECONDS.convert(start-System.nanoTime(), unit);
		}

		@Override
		public int compareTo(Delayed o) {
			long r=getDelay(TimeUnit.NANOSECONDS)-o.getDelay(TimeUnit.NANOSECONDS);
			if (r<0)
				return -1;
			else if (r>0)
				return 1;
			else
				return 0;
		}

		@Override
		boolean take(boolean removeFromList)
		{
			if (super.take(removeFromList))
			{
				if (!removeFromList)
				{
					lock.lock();
					try
					{
						scheduledFutures.remove(this);
					}
					finally {
						lock.unlock();
					}
				}
				return true;
			}
			else
				return false;
		}


	}

	private class DelayedSF<T> extends SF<T>
	{
		private final long delay;
		public DelayedSF(Callable<T> callable, long initialDelay, long delay, TimeUnit unit) {
			super(callable, initialDelay, unit);
			this.delay=unit.toNanos(delay);
		}
		/*public DelayedSF(DelayedSF<T> o) {
			super(o, System.nanoTime()+o.delay);
			this.delay=o.delay;
		}*/

		@Override
		boolean repeat()
		{
			if (isCancelled())
				return false;
			isFinished=false;
			started=false;
			start=System.nanoTime()+delay;
			return true;
		}

		@Override
		public boolean isRepetitive() {
			return !isCancelled();
		}

	}

	private class RatedSF<T> extends SF<T>
	{
		private final long period;
		public RatedSF(Callable<T> callable, long initialDelay, long period, TimeUnit unit) {
			super(callable, initialDelay, unit);
			this.period=unit.toNanos(period);
		}
		/*public RatedSF(RatedSF<T> o) {
			super(o, Math.min(o.start+o.period, System.nanoTime()));
			this.period=o.period;
		}*/

		@Override
		boolean repeat()
		{
			if (isCancelled())
				return false;
			started=false;
			isFinished=false;
			start+=period;
			long c=System.nanoTime();
			if (c>start)
				start=c;
			return true;
		}
		@Override
		public boolean isRepetitive() {
			return !isCancelled();
		}

	}

	@Override
	public List<Runnable> getActualTasks()
	{
		lock.lock();
		try {
			ArrayList<Runnable> l=new ArrayList<>(workQueue.size()+scheduledFutures.size());
			l.addAll(workQueue);
			l.addAll(scheduledFutures);
			return l;
		}
		finally {
			lock.unlock();
		}
	}

	@Override
	public ScheduledFuture<?> schedule(final Runnable command, long delay, TimeUnit unit) {
		if (command==null)
			throw new NullPointerException();
		SF<Void> r=new SF<>(() -> {
			command.run();
			return null;
		}, delay, unit);
		if (delay<=0) {
			execute(r);
			return r;
		}

		return schedule(r);
	}

	@Override
	public <V> ScheduledFuture<V> schedule(Callable<V> callable, long delay, TimeUnit unit) {
		if (callable==null)
			throw new NullPointerException();
		SF<V> r=new SF<>(callable, delay, unit);
		if (delay<=0) {
			execute(r);
			return r;
		}

		return schedule(r);
	}

	@Override
	public ScheduledFuture<?> scheduleAtFixedRate(final Runnable command, long initialDelay, long period, TimeUnit unit) {
		if (command==null)
			throw new NullPointerException();
		return schedule(new RatedSF<>((Callable<Void>) () -> {
			command.run();
			return null;
		}, initialDelay, period, unit));
	}

	@Override
	public ScheduledFuture<?> scheduleWithFixedDelay(final Runnable command, long initialDelay, long delay, TimeUnit unit) {
		if (command==null)
			throw new NullPointerException();
		return schedule(new DelayedSF<>((Callable<Void>) () -> {
			command.run();
			return null;
		}, initialDelay, delay, unit));
	}


	<V> ScheduledFuture<V> schedule(SF<V> sf) {
		if (sf==null)
			throw new NullPointerException();
		lock.lock();
		if (shutdownAsked)
			throw new RejectedExecutionException();
		try {
			repeatUnsafe(sf);
			if (launchThreadIfNecessaryUnsafe())
				waitEventsCondition.signal();
			return sf;
		}finally {
			lock.unlock();
		}
	}

	@Override
	void repeatUnsafe(ScheduledFuture<?> sf) {
		if (shutdownAsked)
			return;
		scheduledFutures.add((SF<?>) sf);
		timeOfFirstOccurrenceInNanos = scheduledFutures.first().start;
	}

	@Override
	boolean areWorkingQueuesEmptyUnsafe() {
		if (super.areWorkingQueuesEmptyUnsafe()) {
			 for (SF<?> f : scheduledFutures)
			 {
				 if (!f.isCancelled() && (!f.isDone() || f.isRepetitive()) && f.getDelay(TimeUnit.NANOSECONDS)<=0)
				 {
					 return false;
				 }
			 }
			 return true;
		}
		else
			return false;
	}
	@Override
	protected void removeRepetitiveTasksUnsafe()
	{
		for (Iterator<SF<?>> it = scheduledFutures.iterator(); it.hasNext(); )
		{
			SF<?> sf=it.next();
			if (sf.isRepetitive())
			{
				sf.cancel(false);
				it.remove();
			}
		}
	}
	protected void cancelAllTasksUnsafe()
	{
		for (SF<?> sf : scheduledFutures)
			sf.cancel(true);
		scheduledFutures.clear();
		timeOfFirstOccurrenceInNanos=Long.MAX_VALUE;
		super.cancelAllTasksUnsafe();
	}

	private Future<?> poolScheduledTask()
	{
		Future<?> r;

		while (timeOfFirstOccurrenceInNanos <=System.nanoTime() && (r= scheduledFutures.pollFirst())!=null) {
			if (scheduledFutures.size() == 0)
				timeOfFirstOccurrenceInNanos = Long.MAX_VALUE;
			else
				timeOfFirstOccurrenceInNanos = scheduledFutures.first().start;

			if (r.take(true)) {
				return r;
			}
		}

		return null;
	}
	@Override
	Future<?> pollTaskUnsafe() {

		if (pull) {

			Future<?> r=poolScheduledTask();
			if (r!=null) {
				pull=false;
				return r;
			}
			else {
				return super.pollTaskUnsafe();
			}
		}
		else {
			Future<?> r=super.pollTaskUnsafe();
			if (r==null)
			{
				return poolScheduledTask();
			}
			else {
				pull = true;
				return r;
			}
		}
	}

	@Override
	long timeToWaitBeforeNewTaskScheduledInNanoSeconds() {
		return timeOfFirstOccurrenceInNanos;
	}
}

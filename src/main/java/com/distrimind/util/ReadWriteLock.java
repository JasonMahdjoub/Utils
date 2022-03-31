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

package com.distrimind.util;

import java.util.HashMap;
import java.util.Map;

/**
 * 
 * @author Jakob Jenkov
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 1.0
 */
public class ReadWriteLock {

	public abstract static class Lock implements AutoCloseable {
		@Override
		public abstract void close();
	}

	public class ReadLock extends Lock {
		protected ReadLock() {
			ReadWriteLock.this.lockRead();
		}

		@Override
		public void close() {
			ReadWriteLock.this.unlockRead();
		}
	}

	public class WriteLock extends Lock {
		protected WriteLock() {
			ReadWriteLock.this.lockWrite();
		}

		@Override
		public void close() {
			ReadWriteLock.this.unlockWrite();
		}
	}

	private final Map<Thread, Integer> readingThreads = new HashMap<>();

	// private ReentrantLock lock=new ReentrantLock(true);
	// private Condition cannotContinue=lock.newCondition();

	private int writeRequests = 0;

	private int writeAccesses = 0;

	private Thread writingThread = null;

	private boolean canGrantReadAccess(Thread callingThread) {
		if (isWriter(callingThread))
			return true;
		if (hasWriter())
			return false;
		if (isReader(callingThread))
			return true;
		return !hasWriteRequests();
	}

	private boolean canGrantWriteAccess(Thread callingThread) {
		if (isWriter(callingThread))
			return true;
		if (isOnlyReader(callingThread) && writingThread == null)
			return true;
		if (hasReaders())
			return false;
		return writingThread == null;
	}

	public ReadLock getAutoCloseableReadLock() {
		return new ReadLock();
	}

	public WriteLock getAutoCloseableWriteLock() {
		return new WriteLock();
	}

	private int getReadAccessCount(Thread callingThread) {
		Integer accessCount = readingThreads.get(callingThread);
		if (accessCount == null)
			return 0;
		return accessCount;
	}

	private boolean hasReaders() {
		return readingThreads.size() > 0;
	}

	private boolean hasWriter() {
		return writingThread != null;
	}

	private boolean hasWriteRequests() {
		return this.writeRequests > 0;
	}

	private boolean isOnlyReader(Thread callingThread) {
		return readingThreads.size() == 1 && readingThreads.get(callingThread) != null;
	}

	private boolean isReader(Thread callingThread) {
		return readingThreads.get(callingThread) != null;
	}

	private boolean isWriter(Thread callingThread) {
		return writingThread == callingThread;
	}

	public void lockRead() {
		while (true) {
			try {
				this.tryLockRead();
				return;
			} catch (InterruptedException e) {
				e.printStackTrace();
			}
		}
	}


	@SuppressWarnings("UnusedReturnValue")
	public int lockWrite() {
		while (true) {
			try {
				return this.tryLockWrite();

			} catch (InterruptedException e) {
				e.printStackTrace();
			}
		}
	}

	@Override
	public String toString() {
		synchronized (this) {
			return "Locker["
					+ (writingThread == null ? (writeAccesses + " Write")
							: (writeAccesses + " x " + writingThread))
					+ "," + (readingThreads.size() == 0 ? "NoReads" : (readingThreads.size() + " Reads")) + "]";
		}
	}

	public void tryLockRead() throws InterruptedException {
		this.tryLockRead(-1);
	}

	public void tryLockRead(long timeout_ms) throws InterruptedException {

		synchronized (this) {
			Thread callingThread = Thread.currentThread();
			while (!canGrantReadAccess(callingThread)) {

				if (timeout_ms < 0)
					wait();
				else
					wait(timeout_ms);

			}

			readingThreads.put(callingThread, (getReadAccessCount(callingThread) + 1));
		}
	}

	public int tryLockWrite() throws InterruptedException {
		return this.tryLockWrite(-1);
	}

	public int tryLockWrite(long timeout_ms) throws InterruptedException {
		synchronized (this) {
			Thread callingThread = Thread.currentThread();
			try {
				++writeRequests;
				while (!canGrantWriteAccess(callingThread)) {
					if (timeout_ms < 0)
						wait();
					else
						wait(timeout_ms);
				}
				--writeRequests;
				writingThread = callingThread;
				return ++writeAccesses;
			} catch (InterruptedException e) {
				--writeRequests;
				notifyAll();
				throw e;
			}
		}
	}

	public void unlockRead() {
		synchronized (this) {

			Thread callingThread = Thread.currentThread();
			if (!isReader(callingThread)) {
				throw new IllegalMonitorStateException(
						"Calling Thread does not" + " hold a read lock on this ReadWriteLock");
			}
			int accessCount = getReadAccessCount(callingThread);
			if (accessCount == 1) {
				readingThreads.remove(callingThread);
			} else {
				readingThreads.put(callingThread, (accessCount - 1));
			}
			notifyAll();
		}
	}

	public void unlockReadAndLockWrite() {
		synchronized (this) {
			unlockRead();
			lockWrite();
		}
	}

	public void unlockWrite() {
		synchronized (this) {
			if (!isWriter(Thread.currentThread())) {
				throw new IllegalMonitorStateException(
						"Calling Thread does not hold the write lock on this ReadWriteLock");
			}
			writeAccesses--;
			if (writeAccesses == 0) {
				writingThread = null;
			}
			if (writeAccesses < 0)
				throw new IllegalMonitorStateException("The number of  unlock is greater than the number of locks");

			notifyAll();
		}

	}

	public void unlockWriteAndLockRead() {
		synchronized (this) {
			unlockWrite();
			lockRead();
		}
	}

}

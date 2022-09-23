package com.distrimind.util.io;
/*
Copyright or © or Copr. Jason Mahdjoub (01/04/2013)

jason.mahdjoub@distri-mind.fr

This software (Object Oriented Database (OOD)) is a computer program 
whose purpose is to manage a local database with the object paradigm 
and the java language

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

import com.distrimind.util.concurrent.LockerCondition;
import com.distrimind.util.concurrent.PoolExecutor;

import java.io.IOException;

/**
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils  4.16.0
 */
public abstract class DelegatedRandomOutputStream extends RandomOutputStream{
	protected RandomOutputStream out;
	private final PoolExecutor pool;

	private volatile IOException exception;
	private final LC lockerCondition;
	private byte[] array;
	private int off, len;

	public DelegatedRandomOutputStream(RandomOutputStream out) {
		this(out, null);
	}
	private class LC extends LockerCondition
	{
		private byte[] a;
		public LC() {
			super(DelegatedRandomOutputStream.this);
		}

		@Override
		public boolean isLocked() {
			if (array!=null)
			{
				a=array;
				return true;
			}
			else
				return false;
		}
		private void releaseArray()
		{
			synchronized (DelegatedRandomOutputStream.this)
			{
				array=null;
				a=null;
				DelegatedRandomOutputStream.this.notify();
			}
		}
		private byte[] getArray()
		{
			return a;
		}
	}
	DelegatedRandomOutputStream(RandomOutputStream out, PoolExecutor poolExecutor) {
		set(out);
		this.pool=poolExecutor;

		if (poolExecutor!=null)
		{
			lockerCondition=new LC();
			array=null;
			poolExecutor.execute(()->{
				while (!isClosed()) {
					try {
						pool.wait(lockerCondition);
						try {
							derivedWrite(lockerCondition.getArray(), off, len);
						}
						finally {
							lockerCondition.releaseArray();
						}
					} catch (InterruptedException e) {
						exception=new IOException(e);
						break;
					} catch (IOException e) {
						exception=e;
						break;
					}
				}
			});

		}
		else
		{
			lockerCondition=null;
		}
		exception=null;
	}

	protected void set(RandomOutputStream out)
	{
		if (out==null)
			throw new NullPointerException();
		this.out = out;
	}

	@Override
	public long length() throws IOException {
		return out.length();
	}

	@Override
	public void setLength(long newLength) throws IOException {
		out.setLength(newLength);
	}

	@Override
	public void seek(long _pos) throws IOException {
		out.seek(_pos);
	}

	@Override
	public long currentPosition() throws IOException {
		return out.currentPosition();
	}

	@Override
	public boolean isClosed() {
		return out.isClosed();
	}

	@Override
	public void write(int b) throws IOException {
		out.write(b);
		multiThreadDerivedWrite(b);
	}
	private void multiThreadDerivedWrite(int b) throws IOException {
		if (pool==null)
			derivedWrite(b);
		else {
			synchronized (this)
			{
				while (array!=null)
				{
					try {
						this.wait();
					} catch (InterruptedException e) {
						throw new IOException(e);
					}
				}
				derivedWrite(b);
			}
		}
	}
	protected abstract void derivedWrite(int b) throws IOException ;


	@Override
	public void write(byte[] b, int off, int len) throws IOException {
		RandomInputStream.checkLimits(b, off, len);
		out.write(b, off, len);
		multiThreadDerivedWrite(b, off, len);
	}

	private void multiThreadDerivedWrite(byte[] b, int off, int len) throws IOException {
		if (pool==null)
			derivedWrite(b, off, len);
		else {
			synchronized (this)
			{
				while (array!=null)
				{
					try {
						this.wait();
					} catch (InterruptedException e) {
						throw new IOException(e);
					}
				}
				this.off=off;
				this.len=len;
				this.array=b;
				lockerCondition.notifyLocker();
			}



		}
	}

	protected abstract void derivedWrite(byte[] b, int off, int len) throws IOException;

	@Override
	public void close() throws IOException {
		if (pool!=null) {
			synchronized (this)
			{
				try {
					while (array != null) {
						try {
							this.wait();
						} catch (InterruptedException e) {
							throw new IOException(e);
						}
					}
				}
				finally {
					out.close();
				}
				if (exception != null)
					throw exception;
			}
		}
		else
			out.close();

	}

	@Override
	public void flush() throws IOException {
		out.flush();
	}


	public RandomOutputStream getOriginalRandomOutputStream()
	{
		return out;
	}

}

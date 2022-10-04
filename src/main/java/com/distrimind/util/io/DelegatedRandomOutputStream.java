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

import com.distrimind.util.concurrent.PoolExecutor;

import java.io.IOException;
import java.util.Arrays;

/**
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils  4.16.0
 */
public abstract class DelegatedRandomOutputStream extends RandomOutputStream{
	protected RandomOutputStream out;

	private final LC thread;
	private final boolean cloneArrays;




	public DelegatedRandomOutputStream(RandomOutputStream out) {
		this(out, null, false);
	}

	static abstract class AbstractLC
	{
		protected byte[] a=null;
		protected byte[] b=null;
		protected int offA, offB, lenA, lenB;
		private boolean releaseArray=false;

		private IOException exception=null;
		private boolean closed=false;

		public AbstractLC(final PoolExecutor pool) {
			super();
			if (pool==null)
				throw new NullPointerException();
			pool.execute(()->{
				pool.incrementMaxThreadNumber();
				try {
					for(;;) {
						try {
							synchronized (AbstractLC.this) {
								if (closed)
									break;
								while (isLocked()) {
									if (closed)
										break;
									AbstractLC.this.wait();
								}
							}
							derivedArrayAction();
						} catch (InterruptedException e) {
							synchronized (AbstractLC.this) {
								exception = new IOException(e);
							}
							break;
						} catch (IOException e) {
							synchronized (AbstractLC.this) {
								exception = e;
							}

							break;
						}
					}
					synchronized (AbstractLC.this)
					{
						a=null;
						b=null;
						AbstractLC.this.notify();
					}
				}
				finally {
					pool.decrementMaxThreadNumber();
				}
			});
		}
		protected final boolean isClosed()
		{
			synchronized (this)
			{
				return closed;
			}
		}


		private boolean isLocked() {
			if (releaseArray)
			{
				releaseArray();
				releaseArray=false;
			}
			if (a!=null) {
				releaseArray=true;
				return false;
			}
			else
				return !isClosed();
		}
		protected abstract void derivedArrayAction() throws IOException ;
		protected abstract void derivedByteAction(int b) throws IOException ;

		private void releaseArray()
		{
			if (b!=null)
			{
				a=b;
				offA=offB;
				lenA=lenB;
				b=null;
				this.notify();
			}
			else {
				a=null;
				this.notify();
			}
		}
		final void addByte(int value) throws IOException {

			synchronized (this) {
				while (a != null) {
					try {
						this.wait();
					} catch (InterruptedException e) {
						throw new IOException(e);
					}
				}
				derivedByteAction(value);
			}
		}
		final void addArray(byte[] t, int off, int len) throws IOException {
			synchronized (this)
			{
				assert b==null;
				if (a==null)
				{
					a=t;
					offA=off;
					lenA=len;
					this.notify();
				}
				else
				{
					if (a==t)
						throw new RuntimeException("The given array is the same than the previous read/write call. Arrays must be switched when cloneArrays is set to false into classes that inherit from DelegatedRandomOutputStream or DelegatedRandomInputStream.");
					b=t;
					offB=off;
					lenB=len;
					while (b!=null)
					{
						try {
							this.wait();
						} catch (InterruptedException e) {
							throw new IOException(e);
						}
					}
				}

			}
		}
		final void flush(boolean close) throws IOException {

			synchronized (this)
			{
				if (closed)
					return;
				try {
					while (a != null) {
						try {
							this.wait();
						} catch (InterruptedException e) {
							throw new IOException(e);
						}
					}
					this.notify();
					if (exception != null)
						throw exception;
				}
				finally {
					if (close)
						closed=true;
				}

			}
		}

	}
	private final class LC extends AbstractLC
	{
		public LC(PoolExecutor poolExecutor) {
			super(poolExecutor);
		}


		@Override
		protected void derivedArrayAction() throws IOException {
			derivedWrite(a, offA, lenA);
		}

		@Override
		protected void derivedByteAction(int b) throws IOException {
			derivedWrite(b);
		}
	}
	DelegatedRandomOutputStream(RandomOutputStream out, PoolExecutor poolExecutor, boolean cloneArrays) {
		set(out);

		this.cloneArrays=cloneArrays;
		if (poolExecutor!=null)
		{
			thread =new LC(poolExecutor);
		}
		else
		{
			thread =null;
		}
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
		return thread==null?out.isClosed(): thread.isClosed();
	}

	@Override
	public void write(int b) throws IOException {
		out.write(b);
		multiThreadDerivedWrite(b);
	}
	private void multiThreadDerivedWrite(int b) throws IOException {
		if (thread ==null)
			derivedWrite(b);
		else {

			thread.addByte(b);
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
		if (thread==null)
			derivedWrite(b, off, len);
		else {
			if (cloneArrays)
				b= Arrays.copyOfRange(b, off, len+off);
			thread.addArray(b, off, len);
		}
	}

	protected abstract void derivedWrite(byte[] b, int off, int len) throws IOException;

	@Override
	public void close() throws IOException {

		if (thread!=null) {

			synchronized (this)
			{
				try {
					thread.flush(true);
				}
				finally {
					out.close();
				}

			}
		}
		else {
			out.close();
		}

	}

	@Override
	public void flush() throws IOException {
		out.flush();
		if (thread !=null)
			thread.flush(false);
	}


	public RandomOutputStream getOriginalRandomOutputStream()
	{
		return out;
	}

}

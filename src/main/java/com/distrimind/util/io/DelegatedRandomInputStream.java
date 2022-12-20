package com.distrimind.util.io;
/*
Copyright or © or Corp. Jason Mahdjoub (01/04/2013)

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

import java.io.DataInputStream;
import java.io.IOException;

/**
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 4.16.0
 */
@SuppressWarnings("NullableProblems")
public abstract class DelegatedRandomInputStream extends RandomInputStream {
	protected RandomInputStream in;
	private final LC thread;


	private final class LC extends DelegatedRandomOutputStream.AbstractLC
	{
		public LC(PoolExecutor poolExecutor, boolean cloneArrays) {
			super(poolExecutor, cloneArrays);
		}


		@Override
		protected void derivedArrayAction() throws IOException {
			derivedRead(a, offA, lenA);
		}

		@Override
		protected void derivedByteAction(int b) throws IOException {
			derivedRead(b);
		}
	}


	public DelegatedRandomInputStream(RandomInputStream in) throws IOException {
		this(in, null, false);
	}
	DelegatedRandomInputStream(RandomInputStream in, PoolExecutor poolExecutor, boolean cloneArrays) throws IOException {
		if (poolExecutor!=null)
		{
			thread =new LC(poolExecutor, cloneArrays);
		}
		else
		{
			thread =null;
		}
		set(in);
	}

	public boolean isMultiThreaded()
	{
		return thread!=null;
	}

	protected void set(RandomInputStream in) throws IOException {
		if (in==null)
			throw new NullPointerException();
		this.flush();
		this.in = in;
		if (thread!=null) {
			thread.init();
			assert !thread.isClosed();
		}
	}

	@Override
	public long length() throws IOException {
		return in.length();
	}

	@Override
	public void seek(long _pos) throws IOException {
		if (thread!=null)
			thread.checkSeekPossible();
		in.seek(_pos);
	}

	@Override
	public long currentPosition() throws IOException {
		return in.currentPosition();
	}

	@Override
	public boolean isClosed() {
		return thread==null?in.isClosed():thread.isClosed();
	}

	@Override
	public void readFully(byte[] tab, int off, int len) throws IOException {
		checkLimits(tab, off, len);
		if (len==0)
			return;
		in.readFully(tab, off, len);
		multiThreadDerivedRead(tab, off, len);
	}

	@Override
	public void skipNBytes(long _nb) throws IOException {
		in.skipNBytes(_nb);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public long skip(long _nb) throws IOException {
		return in.skip(_nb);
	}


	@Override
	@Deprecated
	public String readLine() throws IOException {
		return new DataInputStream(this).readLine();
	}

	@Override
	public int read() throws IOException {
		int v= in.read();
		multiThreadDerivedRead(v);
		return v;
	}

	@Override
	public void mark(int readLimit) {
		in.mark(readLimit);
	}

	@Override
	public boolean markSupported() {
		return in.markSupported();
	}

	@Override
	public void reset() throws IOException {
		in.reset();
	}


	@Override
	public int read(byte[] b, int off, int len) throws IOException {
		checkLimits(b, off, len);
		if (len==0)
			return 0;
		int s= in.read(b, off, len);
		if (s<=0)
			return s;
		multiThreadDerivedRead(b, off, s);
		return s;
	}

	protected abstract void derivedRead(byte[] b, int off, int len) throws IOException;
	protected abstract void derivedRead(int v) throws IOException;

	private void multiThreadDerivedRead(byte[] b, int off, int len) throws IOException {
		if (thread==null)
			derivedRead(b, off, len);
		else {
			thread.addArray(b, off, len);
		}
	}

	private void multiThreadDerivedRead(int b) throws IOException {
		if (thread==null)
			derivedRead(b);
		else {
			thread.addByte(b);
		}
	}

	@Override
	public void close() throws IOException {
		if (thread!=null) {
			synchronized (this)
			{
				try {
					thread.flush(true);

				}
				finally {
					in.close();
				}
			}
		}
		else {
			in.close();
		}
	}

	public RandomInputStream getOriginalRandomInputStream()
	{
		return in;
	}
	@Override
	public void flush() throws IOException {
		if (in!=null) {
			in.flush();
		}
		if (thread != null)
			thread.flush(false);

	}
}

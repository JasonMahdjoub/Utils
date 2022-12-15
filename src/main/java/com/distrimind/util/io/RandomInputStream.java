/*
 * MadKitLanEdition (created by Jason MAHDJOUB (jason.mahdjoub@distri-mind.fr)) Copyright (c)
 * 2015 is a fork of MadKit and MadKitGroupExtension. 
 * 
 * Copyright or © or Corp. Jason Mahdjoub, Fabien Michel, Olivier Gutknecht, Jacques Ferber (1997)
 * 
 * jason.mahdjoub@distri-mind.fr
 * fmichel@lirmm.fr
 * olg@no-distance.net
 * ferber@lirmm.fr
 * 
 * This software is a computer program whose purpose is to
 * provide a lightweight Java library for designing and simulating Multi-Agent Systems (MAS).
 * This software is governed by the CeCILL-C license under French law and
 * abiding by the rules of distribution of free software.  You can  use,
 * modify and/ or redistribute the software under the terms of the CeCILL-C
 * license as circulated by CEA, CNRS and INRIA at the following URL
 * "http://www.cecill.info".
 * As a counterpart to the access to the source code and  rights to copy,
 * modify and redistribute granted by the license, users are provided only
 * with a limited warranty  and the software's author,  the holder of the
 * economic rights,  and the successive licensors  have only  limited
 * liability.
 * 
 * In this respect, the user's attention is drawn to the risks associated
 * with loading,  using,  modifying and/or developing or reproducing the
 * software by the user in light of its specific status of free software,
 * that may mean  that it is complicated to manipulate,  and  that  also
 * therefore means  that it is reserved for developers  and  experienced
 * professionals having in-depth computer knowledge. Users are therefore
 * encouraged to load and test the software's suitability as regards their
 * requirements in conditions enabling the security of their systems and/or
 * data to be ensured and,  more generally, to use and operate it in the
 * same conditions as regards security.
 * The fact that you are presently reading this means that you have had
 * knowledge of the CeCILL-C license and that you accept its terms.
 */
package com.distrimind.util.io;

import java.io.*;

/**
 * 
 * @author Jason Mahdjoub
 * @version 2.0
 * @since Utils 3.27.0
 */
@SuppressWarnings("NullableProblems")
public abstract class RandomInputStream extends SecuredObjectInputStream implements AutoCloseable {
	private long mark = -1;
	private int readLimit = -1;

	/*
	 * public int read(byte[] _bytes) throws IOException; public int read(byte[]
	 * _bytes, int offset, int length) throws InputStreamException;
	 */
	/**
	 * Returns the length of this stream source.
	 *
	 * @return the length of this stream, measured in bytes.
	 * @exception IOException
	 *                if an I/O error occurs.
	 */
	public abstract long length() throws IOException;

	/**
	 * Sets the stream source -pointer offset, measured from the beginning of this
	 * stream, at which the next read or write occurs. The offset may be set beyond
	 * the end of the stream source. Setting the offset or beyond over the end of
	 * the file does not change the file length.
	 *
	 * @param _pos
	 *            the offset position, measured in bytes from the beginning of the
	 *            stream, at which to set the stream source pointer.
	 * @exception IOException
	 *                if <code>pos</code> is less than <code>0</code> or if an I/O
	 *                error occurs.
	 */
	public abstract void seek(long _pos) throws IOException;



	/**
	 * {@inheritDoc}
	 */
	@Override
	public synchronized void mark(int readLimit) {
		if (readLimit > 0) {
			try {
				mark = currentPosition();
				this.readLimit = readLimit;
			} catch (Exception e) {
				mark = -1;
				this.readLimit = -1;
			}
		} else {
			mark = -1;
			this.readLimit = -1;
		}
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean markSupported() {
		return true;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public synchronized void reset() throws IOException {
		if (mark == -1 || mark >= length())
			throw new IOException("Invalid mark : " + mark);
		if (currentPosition() > mark + readLimit)
			throw new IOException("Invalid mark (readLimit reached) : " + mark);
		seek(mark);
	}

	public abstract boolean isClosed();

	@Override
	public final void readFully(byte[] tab) throws IOException {
		readFully(tab, 0, tab==null?0:tab.length);
	}

	@Override
	public abstract void readFully(byte[] tab, int off, int len) throws IOException;


	@Override
	public int available() throws IOException {
		return (int)Math.min(Integer.MAX_VALUE, length()-currentPosition());
	}


	public void skipNBytes(long n) throws IOException {
		if (n<=0)
			return;
		if (skipImpl(n)!=n)
			throw new EOFException();
		/*long l=length();
		if (n<0 || n+currentPosition()>l)
			throw new IllegalArgumentException();

		if (n > 0) {
			long ns = skip(n);
			//noinspection ConstantConditions
			if (ns >= 0 && ns < n) {
				n -= ns;
				while (n > 0 && read() != -1) {
					n--;
				}
				if (n != 0) {
					throw new EOFException();
				}
			} else if (ns != n) {
				throw new IOException("Unable to skip exactly");
			}
		}*/
	}

	public static void checkLimits(byte[] b, int off, int len)
	{
		if (b==null)
			throw new NullPointerException();
		if ((off | len) < 0 || len > b.length - off)
			throw new IndexOutOfBoundsException();
	}

	public void readFully(RandomOutputStream outputStream, long length) throws IOException {
		outputStream.write(this, length);
	}
	public void readFully(RandomOutputStream outputStream) throws IOException {
		outputStream.write(this);
	}

	@Override
	public abstract void close() throws IOException ;

	@Override
	public final int skipBytes(int n) throws IOException {
		return (int)skip(n);
	}

	private long skipImpl(long n) throws IOException {
		if (n<=0)
			return 0;
		long oldp=currentPosition();
		long l=length();
		if (oldp==l)
			return 0;
		long np=Math.min(oldp+n, l);
		seek(np);
		return np-oldp;
	}

	@Override
	public long skip(long n) throws IOException {
		return skipImpl(n);
	}


	public void flush() throws IOException
	{

	}
}

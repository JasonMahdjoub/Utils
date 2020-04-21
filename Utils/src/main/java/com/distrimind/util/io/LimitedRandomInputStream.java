package com.distrimind.util.io;
/*
Copyright or © or Copr. Jason Mahdjoub (01/04/2013)

jason.mahdjoub@distri-mind.fr

This software (Object Oriented Database (OOD)) is a computer program 
whose purpose is to manage a local database with the object paradigm 
and the java langage 

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

import java.io.DataInputStream;
import java.io.IOException;

/**
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 4.16.0
 */
public class LimitedRandomInputStream extends RandomInputStream{
	private final RandomInputStream in;
	private final long off;
	private final long len;

	public LimitedRandomInputStream(RandomInputStream in, long off, long len) throws IOException {
		if (in==null)
			throw new NullPointerException();
		if (off<0 || off>in.length())
			throw new IllegalArgumentException();
		if (len<0)
			throw new IllegalArgumentException();
		if (off+len>in.length())
			throw new IllegalArgumentException();
		this.in = in;
		this.off=off;
		this.len=len;
		in.seek(off);
	}

	@Override
	public long length() {
		return len;
	}

	@Override
	public void seek(long _pos) throws IOException {
		if (_pos < 0 || _pos > length())
			throw new IOException("The given position (" + _pos + ") is invalid. Attempted a position between 0 and "
					+ length() + " excluded.");
		in.seek(_pos+off);
	}

	@Override
	public long currentPosition() throws IOException {
		return in.currentPosition()-off;
	}

	@Override
	public boolean isClosed() {
		return in.isClosed();
	}

	@Override
	public void readFully(byte[] tab, int off, int len) throws IOException {
		checkLimits(tab, off, len);
		in.readFully(tab, off, len);
	}


	/**
	 * {@inheritDoc}
	 */
	@Override
	public long skip(long _nb) throws IOException {
		if (_nb<=0)
			return 0;
		_nb=Math.min(length()-currentPosition(), _nb);
		return in.skip(_nb);
	}


	@Override
	@Deprecated
	public String readLine() throws IOException {
		return new DataInputStream(this).readLine();
	}

	@Override
	public int read() throws IOException {
		if (currentPosition()>=length())
			return -1;
		return in.read();
	}

	@Override
	public void mark(int readlimit) {
		in.mark((int)(readlimit+off));
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
		int s = Math.min((int)Math.min(Integer.MAX_VALUE, length()-currentPosition()), len);
		return in.read(b, off, s);
	}

	@Override
	public void close() throws IOException {
		in.close();
	}


}

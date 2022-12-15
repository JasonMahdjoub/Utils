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
package com.distrimind.util.io;

import java.io.DataInputStream;
import java.io.EOFException;
import java.io.IOException;

/**
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 4.16.0
 */
@SuppressWarnings("NullableProblems")
public class FragmentedRandomInputStream extends RandomInputStream{
	private final RandomInputStream[] ins;
	private final FragmentedStreamParameters parameters;
	private int sindex;
	private long pos;
	private boolean closed;

	public FragmentedRandomInputStream(FragmentedStreamParameters parameters, RandomInputStream... ins) throws IOException {
		if (ins==null)
			throw new NullPointerException();
		if (parameters==null)
			throw new NullPointerException();
		if (parameters.getStreamPartNumbers()!=ins.length)
			throw new IllegalArgumentException();
		for (RandomInputStream in : ins)
			if (in==null)
				throw new NullPointerException();
		this.ins = ins.clone();
		this.parameters = parameters;
		this.closed=false;
		seek(0);
	}
	FragmentedRandomInputStream(FragmentedStreamParameters parameters, RandomInputStream[] ins, boolean closed) throws IOException {
		this.ins = ins;
		this.parameters = parameters;

		this.closed=closed;
		if (closed)
			this.pos=0;
		else {
			seek(0);
			/*this.pos=ins[0].currentPosition();
			for (int i = 1; i < ins.length; i++)
				this.pos += ins[i].currentPosition();*/
		}
		//this.sindex=(int)(pos%ins.length);
	}

	public FragmentedStreamParameters getParameters() {
		return parameters;
	}

	@Override
	public long length() throws IOException {
		long l=ins[0].length();
		for (int i=1;i<ins.length;i++)
			l+=ins[i].length();
		return l;
	}

	@Override
	public void seek(long _pos) throws IOException {
		if (isClosed())
			throw new IOException("Stream closed");

		this.pos=_pos;
		long p=_pos/ins.length;
		sindex=(int)(_pos%ins.length);
		for (int i=0;i<ins.length;i++) {
			if (i<sindex)
				ins[i].seek(p+1);
			else
				ins[i].seek(p);
		}
	}

	@Override
	public long currentPosition() {
		return pos;
	}

	@Override
	public int read() throws IOException {
		if (isClosed())
			throw new IOException("Stream closed");
		int v=ins[sindex].read();
		if (v>=0) {
			sindex = (sindex+1)%ins.length;
			++pos;
		}
		return v;
	}

	@Override
	public int read(byte[] b, int off, int len) throws IOException {
		return read(b, off, len, false);
	}
	private int read(byte[] b, int off, int len, boolean fully) throws IOException {
		if (isClosed())
			throw new IOException("Stream closed");
		checkLimits(b, off, len);
		int end=off+len;
		for (int i=off;i<end;i++) {
			int v = ins[sindex].read();
			if (v >= 0) {
				sindex = (sindex + 1) % ins.length;
				++pos;
				b[i]=(byte)v;
			}
			else {
				if (fully)
					throw new EOFException();
				i-=off;
				if (i==0)
					return -1;
				else
					return i;
			}
		}
		return len;
	}

	@Override
	public void readFully(byte[] tab, int off, int len) throws IOException {
		//noinspection ResultOfMethodCallIgnored
		read(tab, off, len, true);
	}




	@Override
	@Deprecated
	public String readLine() throws IOException {
		if (isClosed())
			throw new IOException("Stream closed");
		return new DataInputStream(this).readLine();
	}
	@Override
	public boolean isClosed() {
		return closed;
	}
	@Override
	public void close() throws IOException {
		if (closed)
			return;
		for (RandomInputStream in : ins)
			in.close();
		closed=true;
	}

	@Override
	public void flush() throws IOException {
		for (RandomInputStream r : this.ins)
			r.flush();
	}
}

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
package com.distrimind.util.io;

import java.io.IOException;

/**
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 4.16.0
 */
public class FragmentedRandomOutputStream extends RandomOutputStream {
	private final RandomOutputStream[] outs;
	private final FragmentedStreamParameters parameters;
	private long length=0;
	private int sindex=0;
	private long pos;
	private boolean closed=false;
	public FragmentedRandomOutputStream(FragmentedStreamParameters parameters, RandomOutputStream ...outs) throws IOException {
		if (outs==null)
			throw new NullPointerException();
		if (parameters==null)
			throw new NullPointerException();
		if (parameters.getStreamPartNumbers()!=outs.length)
			throw new IllegalArgumentException();
		for (RandomOutputStream out : outs)
			if (out==null)
				throw new NullPointerException();
		this.outs = outs;
		this.parameters = parameters;
		seek(0);
	}

	@Override
	public long length() {
		return length;
	}

	@Override
	public void setLength(long newLength) throws IOException {
		long p=newLength/outs.length;
		for (int i=0;i<outs.length;i++)
		{
			outs[i].setLength(p+(i<newLength%outs.length?1:0));
		}
		this.length=newLength;
		this.pos=Math.min(this.pos, this.length);
	}

	@Override
	public void seek(long _pos) throws IOException {
		this.pos=_pos;
		long p=_pos/outs.length;
		sindex=(int)(_pos%outs.length);
		for (RandomOutputStream out : outs) out.seek(p);
	}

	@Override
	public long currentPosition() {
		return pos;
	}

	@Override
	public boolean isClosed() {
		return closed;
	}



	@Override
	public void close() throws IOException {
		if (closed)
			return;
		for (RandomOutputStream out : outs)
		{
			out.close();
		}
		closed=true;
	}

	@Override
	public void write(byte[] b, int off, int len) throws IOException {
		if ((off | len) < 0 || len > b.length - off)
			throw new IndexOutOfBoundsException();
		int end=off+len;
		for (int i=off;i<end;i++)
		{
			outs[sindex++].write(b);
			sindex%=outs.length;
		}
		pos+=len;
		length=Math.max(pos, length);
	}

	@Override
	public void write(int b) throws IOException {
		outs[sindex++].write(b);
		sindex%=outs.length;
		pos++;
		length=Math.max(pos, length);
	}
	@Override
	public void flush() throws IOException {
		for (RandomOutputStream out : outs)
		{
			out.flush();
		}
	}
	@Override
	protected RandomInputStream getRandomInputStreamImpl() throws IOException {
		RandomInputStream[] ins=new RandomInputStream[outs.length];
		for (int i=0;i<outs.length;i++)
			ins[i]=outs[i].getRandomInputStream();

		return new FragmentedRandomInputStream(parameters, ins, closed);
	}
}

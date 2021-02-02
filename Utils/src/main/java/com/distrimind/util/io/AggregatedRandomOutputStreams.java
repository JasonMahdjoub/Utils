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

import java.io.EOFException;
import java.io.IOException;

/**
 * @author Jason Mahdjoub
 * @version 1.1
 * @since Utils 4.16.0
 */
public class AggregatedRandomOutputStreams extends RandomOutputStream {
	private final RandomOutputStream[] outs;
	private final long[] lengths;
	private int selectedOutputStreamPos;
	private long posOff;
	private boolean closed;
	public AggregatedRandomOutputStreams(RandomOutputStream[] outs, long[] lengths) throws IOException {
		this(outs, lengths, false);
	}
	public AggregatedRandomOutputStreams(RandomOutputStream[] outs, long[] lengths, boolean reserveSpace) throws IOException {
		if (outs==null)
			throw new NullPointerException();
		if (outs.length==0)
			throw new IllegalArgumentException();
		if (lengths==null)
			throw new NullPointerException();
		if (lengths.length!=outs.length)
			throw new IllegalArgumentException();

		for (RandomOutputStream o : outs)
			if (o==null)
				throw new NullPointerException();

		for (int i=0;i<lengths.length;i++) {
			long l=lengths[i];
			if (l <= 0)
				throw new IllegalArgumentException();
			if (reserveSpace && i+1!=lengths.length)
				outs[i].setLength(l);
		}
		this.outs = outs;
		this.lengths=lengths;
		selectedOutputStreamPos =0;
		posOff=0;
		closed=false;
		outs[0].seek(0);
	}

	@Override
	public long length() throws IOException {
		long l=0;
		for (int i=0;i<outs.length;i++)
			l+=Math.min(outs[i].length(), lengths[i]);
		return l;
	}

	@Override
	public void write(int b) throws IOException {
		RandomOutputStream ros=actualizeCurrentOutputStream(true);
		ros.write(b);
	}
	private RandomOutputStream actualizeCurrentOutputStream(boolean wantToWrite) throws IOException {
		RandomOutputStream ros=outs[selectedOutputStreamPos];
		long l=lengths[selectedOutputStreamPos];
		if (ros.currentPosition()==l)
		{
			if (++selectedOutputStreamPos ==outs.length) {
				--selectedOutputStreamPos;
				if (wantToWrite)
					throw new EOFException();
				else
					return ros;
			}
			else {
				posOff+=l;
				ros = outs[selectedOutputStreamPos];
				ros.seek(0);
			}
		}
		return ros;
	}

	@Override
	public void write(byte[] tab, int off, int len) throws IOException {
		if (closed)
			throw new IOException("Stream closed");
		//ensureLength(currentPosition()+len);
		RandomInputStream.checkLimits(tab, off, len);
		do {
			RandomOutputStream ros=actualizeCurrentOutputStream(true);

			int s=(int)Math.min(len, lengths[selectedOutputStreamPos]-ros.currentPosition());

			ros.write(tab, off, s);
			off += s;
			len -= s;
		} while(len>0);
	}

	@Override
	public void setLength(long newLength) throws IOException {
		long acc=0;
		long curPos=currentPosition();
		for (int i=0;i<outs.length;i++)
		{
			if (acc>=newLength)
			{
				outs[i].setLength(0);
			}
			else
			{
				long l=acc+lengths[i];
				if (l>=newLength)
					outs[i].setLength(newLength-acc);
				else
					outs[i].ensureLength(lengths[i]);
				acc=l;
			}
		}
		if (curPos>newLength)
			seek(newLength);
	}

	@Override
	public void seek(long _pos) throws IOException {
		if (closed)
			throw new IOException("Stream closed");
		if (_pos<0)
			throw new IllegalArgumentException();
		long off=0;
		for (int i=0;i<outs.length;i++)
		{
			RandomOutputStream ris = outs[i];
			long l=lengths[i];
			boolean last=i+1==outs.length;
			if ((last && l >= _pos - off) || (!last && l > _pos - off))
			{
				ris.seek(_pos-off);
				posOff=off;
				this.selectedOutputStreamPos =i;
				return;
			}
			else
				off+=l;
		}
		throw new IllegalArgumentException();
	}

	@Override
	public long currentPosition() throws IOException {
		return actualizeCurrentOutputStream(false).currentPosition()+posOff;
	}

	@Override
	public boolean isClosed() {
		return closed;
	}

	@Override
	protected RandomInputStream getRandomInputStreamImpl() throws IOException {
		RandomInputStream[] ins=new RandomInputStream[outs.length];
		for (int i=0;i<outs.length;i++) {
			long l=lengths[i];
			long l2=outs[i].length();
			if (l==l2)
				ins[i] = outs[i].getRandomInputStream();
			else
				ins[i] = new LimitedRandomInputStream(outs[i].getRandomInputStream(), 0, Math.min(l,l2));
		}
		return new AggregatedRandomInputStreams(ins);
	}

	@Override
	public void flush() throws IOException {
		for (RandomOutputStream out : outs)
			out.flush();
	}

	@Override
	public void close() throws IOException {
		if (!closed)
		{
			for (RandomOutputStream out : outs)
				out.close();
			closed=true;
		}
	}
}

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
import java.io.EOFException;
import java.io.IOException;
import java.util.List;

/**
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 4.16.0
 */
public class AggregatedRandomInputStreams extends RandomInputStream{

	private final RandomInputStream[] inputStreams;
	private final long length;
	private int selectedInputStreamPos;
	private long posOff;
	private boolean closed;


	public AggregatedRandomInputStreams(RandomInputStream... inputStreams) throws IOException {
		if (inputStreams==null)
			throw new NullPointerException();
		else if (inputStreams.length==0)
			throw new IllegalArgumentException();
		long l=0;
		for (RandomInputStream ris : inputStreams) {
			if (ris == null)
				throw new NullPointerException();
			l += ris.length();
		}
		this.inputStreams = inputStreams.clone();
		this.length=l;
		this.posOff=0;
		this.selectedInputStreamPos=0;
		this.inputStreams[0].seek(0);
		this.closed=false;

	}

	public AggregatedRandomInputStreams(List<RandomInputStream> inputStreams) throws IOException {
		this((RandomInputStream[])inputStreams.toArray());
	}

	@Override
	public long length() {
		return length;
	}

	@Override
	public void seek(long _pos) throws IOException {
		if (closed)
			throw new IOException("Stream closed");
		if (_pos<0)
			throw new IllegalArgumentException();
		long off=0;
		for (int i=0;i<inputStreams.length;i++)
		{
			RandomInputStream ris = inputStreams[i];
			long l=ris.length();
			if (l>(_pos-off))
			{
				ris.seek(_pos-off);
				posOff=off;
				this.selectedInputStreamPos=i;
				return;
			}
			else
				off+=l;
		}
		throw new IllegalArgumentException();
	}

	@Override
	public long currentPosition() throws IOException {
		return inputStreams[selectedInputStreamPos].currentPosition()+posOff;
	}

	@Override
	public boolean isClosed() {
		return closed;
	}

	@Override
	public boolean markSupported() {
		return false;
	}

	@Override
	public void close() throws IOException {
		if (closed)
			return;
		for (RandomInputStream ris : inputStreams)
			ris.close();
		closed=true;
	}

	@Override
	public void readFully(byte[] tab, int off, int len) throws IOException {
		if (closed)
			throw new IOException("Stream closed");
		checkLimits(tab, off, len);
		if (len==0)
			return;
		RandomInputStream ris=inputStreams[selectedInputStreamPos];
		do {
			if (ris.currentPosition()==ris.length())
			{
				if (++selectedInputStreamPos==inputStreams.length) {
					--selectedInputStreamPos;
					throw new EOFException();
				}
				else {
					posOff+=ris.length();
					ris = inputStreams[selectedInputStreamPos];
					ris.seek(0);
				}
			}
			int s=(int)Math.min(len, ris.length()-ris.currentPosition());
			if (s>0)
				ris.readFully(tab, off, s);
			off+=s;
			len-=s;

		} while(len>0);
	}

	@Override
	@Deprecated
	public String readLine() throws IOException {
		if (closed)
			throw new IOException("Stream closed");
		return new DataInputStream(this).readLine();
	}

	@Override
	public int read() throws IOException {
		if (closed)
			throw new IOException("Stream closed");
		RandomInputStream ris=inputStreams[selectedInputStreamPos];
		if (ris.currentPosition()==ris.length())
		{
			if (++selectedInputStreamPos==inputStreams.length) {
				--selectedInputStreamPos;
				return -1;
			}
			else {
				posOff+=ris.length();
				ris = inputStreams[selectedInputStreamPos];
				ris.seek(0);
			}
		}

		return ris.read();
	}

	@Override
	public int read(byte[] tab, int off, int len) throws IOException {
		if (closed)
			throw new IOException("Stream closed");
		checkLimits(tab, off, len);
		RandomInputStream ris=inputStreams[selectedInputStreamPos];
		int total=0;
		do {
			if (ris.currentPosition()==ris.length())
			{
				if (++selectedInputStreamPos==inputStreams.length) {
					--selectedInputStreamPos;
					if (total==0)
						return -1;
					else
						return total;
				}
				else {
					posOff+=ris.length();
					ris = inputStreams[selectedInputStreamPos];
					ris.seek(0);
				}
			}
			int s=(int)Math.min(len, ris.length()-ris.currentPosition());

			if (s>0)
				s=ris.read(tab, off, s);
			if (s>0) {
				off += s;
				len -= s;
				total+=s;
			} else if (s<0)
			{
				if (total==0)
					return -1;
				else
					return total;
			}
		} while(len>0);
		return total;
	}
}

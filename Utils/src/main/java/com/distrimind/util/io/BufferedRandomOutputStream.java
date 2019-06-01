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

import java.io.IOException;
import java.util.Arrays;

import static com.distrimind.util.io.BufferedRandomInputStream.MAX_BUFFER_SIZE;
import static com.distrimind.util.io.BufferedRandomInputStream.MAX_BUFFERS_NUMBER;

/**
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 3.30.0
 */
public class BufferedRandomOutputStream extends RandomOutputStream{
	private RandomOutputStream out;

	private final byte[][] buffers;
	private final long[] positions;
	private final int[] endPositions;
	private byte[] currentBuffer=null;
	private int currentBufferIndex=0;
	private int previousChosenBufferIndex ;
	private long currentPosition=0;
	private final int maxBufferSize;

	public BufferedRandomOutputStream(RandomOutputStream out) {
		this(out, MAX_BUFFER_SIZE);
	}
	public BufferedRandomOutputStream(RandomOutputStream out, int maxBufferSize) {
		this(out, maxBufferSize, MAX_BUFFERS_NUMBER);
	}
	public BufferedRandomOutputStream(RandomOutputStream out, int maxBufferSize, int maxBuffersNumber) {
		this.out = out;
		this.maxBufferSize=maxBufferSize;
		buffers=new byte[maxBuffersNumber][maxBufferSize];
		positions=new long[maxBuffersNumber];
		endPositions=new int[maxBuffersNumber];
		previousChosenBufferIndex=maxBuffersNumber-1;
		Arrays.fill(positions, -1);
		Arrays.fill(endPositions, 0);
	}

	private void chooseBuffer(long _pos) throws IOException {
		currentBuffer=null;
		previousChosenBufferIndex =currentBufferIndex;
		currentBufferIndex=0;
		for (int i=0;i<positions.length;i++) {
			long p=positions[i];
			if (p>=0)
			{
				if (_pos>p && _pos<p+maxBufferSize)
				{
					currentBuffer = buffers[i];
					currentBufferIndex = i;
					if (endPositions[i]!=_pos) {
						flush(i, _pos);
					}
					break;
				}
				else if (_pos>=p-maxBufferSize && _pos<p)
				{
					flush(i, _pos);
					currentBuffer = buffers[i];
					currentBufferIndex = i;
					break;
				}
			}
		}
	}

	private void flush(int bufferIndex, long newPos) throws IOException {

		int len=endPositions[bufferIndex];
		if (len>0)
		{
			long oldPos=out.currentPosition();
			long pos=positions[bufferIndex];
			if (pos!=oldPos)
				out.seek(pos);
			out.write(buffers[bufferIndex], 0, len);
			endPositions[bufferIndex]=0;
			positions[bufferIndex]=newPos;
		}

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
		currentPosition=_pos;
		chooseBuffer(_pos);
	}

	@Override
	public long currentPosition() {
		return currentPosition;
	}

	@Override
	public boolean isClosed() {
		return out.isClosed();
	}

	@Override
	protected BufferedRandomInputStream getRandomInputStreamImpl() {
		return new BufferedRandomInputStream(out.getRandomInputStreamImpl());
	}


	private void checkCurrentBufferNotNull() throws IOException {
		if (currentBuffer==null)
		{
			if (previousChosenBufferIndex ==0 && positions.length>1)
				currentBufferIndex=1;
			else
				currentBufferIndex=0;

			currentBuffer=buffers[currentBufferIndex];

			if (positions[currentBufferIndex]!=-1) {
				flush(currentBufferIndex, currentPosition);
			}
		} else
		{
			if (positions[currentBufferIndex]+maxBufferSize>=currentPosition) {
				flush(currentBufferIndex, currentPosition);
			}
		}
	}

	@Override
	public void write(int b) throws IOException {
		checkCurrentBufferNotNull();
		currentBuffer[endPositions[currentBufferIndex]++]=(byte)b;
		++currentPosition;
	}

	@Override
	public void ensureLength(long length) throws IOException {
		if (length<out.length())
			flush();
		out.ensureLength(length);
	}

	@Override
	public void write(byte[] b, int off, int len) throws IOException {
		checkCurrentBufferNotNull();
		int curPos=endPositions[currentBufferIndex];
		while(len>0)
		{
			if (curPos==0 && len>=maxBufferSize)
			{
				out.write(b, off, len);
				currentPosition+=len;
				chooseBuffer(currentPosition);
				return;
			}
			int l=Math.min(maxBufferSize-curPos, len);
			System.arraycopy(b, off, currentBuffer, curPos, l);
			curPos=(endPositions[currentBufferIndex]+=l);
			len-=l;
			currentPosition+=l;
			off+=l;
			if (curPos==maxBufferSize) {
				flush(currentBufferIndex, currentPosition);
				curPos = 0;
			}
		}
	}

	@Override
	public void flush() throws IOException {
		for (int i=0;i<maxBufferSize;i++)
			flush(i, currentPosition);
		out.flush();
	}

	@Override
	public void close() throws IOException {
		for (int i=0;i<maxBufferSize;i++)
			flush(i, currentPosition);
		out.close();
	}



}

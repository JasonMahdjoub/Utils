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
 * @version 1.1
 * @since Utils 3.30.0
 */
public class BufferedRandomOutputStream extends RandomOutputStream{
	private RandomOutputStream out;

	private final byte[][] buffers;
	private final long[] positions;
	private final int[] endPositions;
	private byte[] currentBuffer=null;
	private int currentBufferIndex=-1;

	private long currentPosition;
	private final int maxBufferSize;
	private final int maxBufferSizeDiv2;
	private final int maxBuffersNumber;
	private long length;

	public BufferedRandomOutputStream(RandomOutputStream out) throws IOException {
		this(out, MAX_BUFFER_SIZE);
	}
	public BufferedRandomOutputStream(RandomOutputStream out, int maxBufferSize) throws IOException {
		this(out, maxBufferSize, MAX_BUFFERS_NUMBER);
	}
	public BufferedRandomOutputStream(RandomOutputStream out, int maxBufferSize, int maxBuffersNumber) throws IOException {
		this.out = out;
		this.maxBufferSize=maxBufferSize;
		this.maxBufferSizeDiv2=maxBufferSize/2;
		this.maxBuffersNumber=maxBuffersNumber;
		buffers=new byte[maxBuffersNumber][maxBufferSize];
		positions=new long[maxBuffersNumber];
		endPositions=new int[maxBuffersNumber];

		Arrays.fill(positions, -1);
		Arrays.fill(endPositions, 0);
		this.currentPosition=out.currentPosition();
		this.length=out.length();
	}

	private void checkOverlapping() throws IOException {
		currentBuffer=null;
		currentBufferIndex=-1;
		for (int i=0;i<maxBuffersNumber;i++) {
			long p=positions[i];
			if (p!=-1 && isOverlapped(p, currentPosition)) {
				flush(i, -1);
			}
		}

	}

	public RandomOutputStream getRandomOutputStreamSource() {
		return out;
	}

	private void changePosition(int bufferIndex, long newPos) throws IOException {
		//assert endPositions[bufferIndex]==0;
		if (newPos==-1) {
			positions[bufferIndex]=-1;

			/*if (bufferIndex==currentBufferIndex)
				throw new InternalError();*/
			return;
		}
		else {
			if (positions[bufferIndex]==newPos)
				return;
			positions[bufferIndex] = newPos;
		}
		for (int i=0;i<maxBuffersNumber;i++)
		{
			if (i!=bufferIndex)
			{
				long p=positions[i];
				if (p!=-1 && isOverlapped(p, newPos))
				{
					int len=endPositions[i];
					//assert len<=maxBufferSize;
					if (len>0) {
						out.seek(p);
						out.write(buffers[i], 0, len);
						endPositions[i]=0;
					}
					positions[i]=-1;
				}
			}
		}
	}
	private boolean isOverlapped(long position, long newPos)
	{
		return isOverlapped(position, newPos, maxBufferSize);
	}
	private boolean isOverlapped(long position, long newPos, int len)
	{
		return position+maxBufferSize>newPos && position<newPos+len;
	}
	private void flush(int bufferIndex, long newPos) throws IOException {
		int len=endPositions[bufferIndex];

		if (len>0)
		{
			long pos=positions[bufferIndex];
			if (pos!=-1) {
				/*long oldPos=out.currentPosition();
				if (pos != oldPos)*/

				out.seek(pos);
				//assert len<=maxBufferSize;
				out.write(buffers[bufferIndex], 0, len);
				endPositions[bufferIndex] = 0;

				changePosition(bufferIndex, newPos);

			}
			/*else
				throw new InternalError();*/

		}
		else {
			changePosition(bufferIndex, newPos);
		}
	}

	@Override
	public long length()  {
		return length;
	}

	@Override
	public void setLength(long newLength) throws IOException {
		if (newLength<0)
			throw new IllegalArgumentException();


		length=newLength;
		for (int i=0;i<maxBuffersNumber;i++)
		{
			if (positions[i]!=-1) {
				if (positions[i] > newLength) {
					positions[i] = -1;
					endPositions[i]=0;
				}
				else
					endPositions[i]=(int)Math.min(newLength-positions[i], endPositions[i]);
			}
		}
		out.setLength(newLength);
		if (currentPosition>newLength) {
			currentPosition = newLength;
			checkOverlapping();
		}



	}

	@Override
	public void seek(long _pos) throws IOException {
		if (_pos<0 || _pos>length())
			throw new IllegalArgumentException();
		currentPosition=_pos;
		checkOverlapping();
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
	protected BufferedRandomInputStream getRandomInputStreamImpl() throws IOException {
		flush();
		return new BufferedRandomInputStream(out.getRandomInputStream(), maxBufferSize, maxBuffersNumber);
	}

	@Override
	public RandomInputStream getUnbufferedRandomInputStream() throws IOException {
		flush();
		return out.getUnbufferedRandomInputStream();
	}


	private void checkCurrentBufferNotNull() throws IOException {
		if (currentBuffer==null)
		{
			//assert currentBufferIndex==-1;

			long best=Long.MAX_VALUE;
			for (int i = 0; i < maxBuffersNumber; i++) {
				if (positions[i] == -1) {
					positions[i]=currentPosition;
					currentBufferIndex = i;
					currentBuffer=buffers[currentBufferIndex];
					return;
				} else {
					long v = Math.abs(positions[i] - currentPosition);
					if (best > v) {
						best = v;
						currentBufferIndex = i;
					}
				}
			}
			currentBuffer=buffers[currentBufferIndex];

			flush(currentBufferIndex, currentPosition);


		} /*else
		{
			long pos=positions[currentBufferIndex];
			if (pos>currentPosition)
				throw new IllegalAccessError();
			if (pos+maxBufferSize>=currentPosition) {
				flush(currentBufferIndex, currentPosition);
			}
		}*/
	}

	@Override
	public void write(int b) throws IOException {
		checkCurrentBufferNotNull();

		currentBuffer[endPositions[currentBufferIndex]++]=(byte)b;
		++currentPosition;
		length=Math.max(currentPosition, length);
		if (endPositions[currentBufferIndex]==maxBufferSize)
			flush(currentBufferIndex, currentPosition);

	}

	@Override
	public void ensureLength(long length) throws IOException {
		if (length<0)
			throw new IllegalArgumentException();
		//flush();

		if (length>this.length) {
			out.ensureLength(length);
			this.length = length;
		}
	}

	@Override
	public void write(byte[] b, int off, int len) throws IOException {
		checkCurrentBufferNotNull();
		int curPos=endPositions[currentBufferIndex];
		while(len>0)
		{
			if (curPos==0 && len>=maxBufferSizeDiv2)
			{
				currentBuffer=null;
				currentBufferIndex=-1;
				for (int i=0;i<maxBuffersNumber;i++)
				{
					long p=positions[i];

					if (p!=-1) {
						/*if (p >= currentPosition && p < newPos)
							flush(i, (int)(newPos-p), -1, -1);
						else if (p<currentPosition && p+maxBufferSize>currentPosition)
						{
							flush(i, 0, -1, (int)(currentPosition-p));
						}*/
						if (isOverlapped(p, currentPosition, len))
							flush(i, p);
					}
				}
				out.seek(currentPosition);
				out.write(b, off, len);
				currentPosition+=len;
				length=Math.max(currentPosition, length);
				checkOverlapping();
				return;
			}
			int l=Math.min(maxBufferSize-curPos, len);
			System.arraycopy(b, off, currentBuffer, curPos, l);
			curPos=(endPositions[currentBufferIndex]+=l);
			len-=l;
			currentPosition+=l;
			length=Math.max(currentPosition, length);
			off+=l;
			if (curPos==maxBufferSize) {

				flush(currentBufferIndex, currentPosition);
				curPos = 0;
			}
			/*else if (curPos>maxBufferSize)
				throw new InternalError();*/
		}
	}

	@Override
	public void flush() throws IOException {
		currentBuffer=null;
		currentBufferIndex=-1;
		for (int i=0;i<maxBuffersNumber;i++) {
			flush(i, -1);
		}
		out.flush();
	}

	@Override
	public void close() throws IOException {
		flush();
		out.close();
	}



}

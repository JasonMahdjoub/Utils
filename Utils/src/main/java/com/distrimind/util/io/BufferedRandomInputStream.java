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

/**
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 3.30.0
 */
public class BufferedRandomInputStream extends RandomInputStream {

	static final int MAX_BUFFERS_NUMBER=3;
	static final int MAX_BUFFER_SIZE=8192;

	private final RandomInputStream in;
	private final byte[][] buffers;
	private final long[] positions;
	private byte[] currentBuffer=null;
	private int currentBufferIndex=0;
	private int previousChosenBufferIndex ;
	private long currentPosition=0;
	private final int maxBufferSize;

	public BufferedRandomInputStream(RandomInputStream in) {
		this(in, MAX_BUFFER_SIZE);
	}
	public BufferedRandomInputStream(RandomInputStream in, int maxBufferSize) {
		this(in, maxBufferSize, MAX_BUFFERS_NUMBER);
	}
	public BufferedRandomInputStream(RandomInputStream in, int maxBufferSize, int maxBuffersNumber) {
		this.in = in;
		this.maxBufferSize=maxBufferSize;
		this.previousChosenBufferIndex=maxBuffersNumber-1;
		buffers=new byte[maxBuffersNumber][maxBufferSize];
		positions=new long[maxBuffersNumber];
		Arrays.fill(positions, -1);
	}

	@Override
	public long length() throws IOException {
		return in.length();
	}

	private void chooseBuffer(long _pos)
	{
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
					break;
				}
				else if (_pos>=p-maxBufferSize && _pos<p)
				{
					currentBuffer = buffers[i];
					currentBufferIndex = i;
					positions[i]=_pos;
					break;
				}
			}
		}
	}

	@Override
	public void seek(long _pos) {
		chooseBuffer(_pos);
		currentPosition=_pos;
	}

	@Override
	public long currentPosition() {
		return currentPosition;
	}

	@Override
	public boolean isClosed() {
		return in.isClosed();
	}

	private void checkCurrentBufferNotNull(int len) throws IOException {
		if (currentBuffer==null)
		{
			if (previousChosenBufferIndex ==0 && positions.length>1)
				currentBufferIndex=1;
			else
				currentBufferIndex=0;

			currentBuffer=buffers[currentBufferIndex];

			positions[currentBufferIndex]=currentPosition;
			in.seek(currentPosition);
			in.readFully(currentBuffer, 0, Math.min(maxBufferSize, len));
		}
 	}

	@Override
	public void readFully(byte[] tab, int off, int len) throws IOException {

		checkCurrentBufferNotNull(len);
		boolean first=true;
		while(len>0)
		{
			long curPos=positions[currentBufferIndex];

			if (currentPosition>=curPos+maxBufferSize)
			{
				curPos=positions[currentBufferIndex]=currentPosition;
				if (first) {
					in.seek(currentPosition);
					first=false;
				}
				in.readFully(currentBuffer, 0, Math.min(maxBufferSize, len));
			}
			int bufPos=(int)(currentPosition-curPos);
			int copyLen=Math.min(len, maxBufferSize-bufPos);
			System.arraycopy(currentBuffer, bufPos, tab, off, copyLen);
			len-=copyLen;
			off+=copyLen;
			currentPosition+=copyLen;
		}

	}

	@Override
	public int skipBytes(int n) throws IOException {
		long oldPos=currentPosition;
		currentPosition=Math.min(currentPosition+n, in.length());
		n=(int)(currentPosition-oldPos);
		chooseBuffer(currentPosition);
		return n;
	}

	@Override
	public String readLine() throws IOException {
		in.seek(currentPosition);
		try {
			return in.readLine();
		}
		finally {
			currentPosition=in.currentPosition();
			chooseBuffer(currentPosition);
		}
	}

	@Override
	public int read() throws IOException {

		long len=in.length()-currentPosition;
		checkCurrentBufferNotNull((int)Math.min(Integer.MAX_VALUE, len));
		long curPos=positions[currentBufferIndex];
		if (currentPosition>=curPos+maxBufferSize)
		{
			curPos=positions[currentBufferIndex]=currentPosition;
			in.seek(currentPosition);
			in.readFully(currentBuffer, 0, (int)Math.min(maxBufferSize, len));
		}
		return currentBuffer[(int)((currentPosition++)-curPos)];
	}

	@Override
	public synchronized void mark(int readlimit) {
		try {
			in.seek(currentPosition);
		} catch (IOException e) {
			e.printStackTrace();
		}
		in.mark(readlimit);
	}

	@Override
	public boolean markSupported() {
		try {
			in.seek(currentPosition);
		} catch (IOException e) {
			e.printStackTrace();
		}
		return in.markSupported();
	}

	@Override
	public synchronized void reset() throws IOException {
		in.seek(currentPosition);
		in.reset();
	}

	@Override
	public int read(byte[] b, int off, int len) throws IOException {
		checkCurrentBufferNotNull(len);
		int res=0;
		boolean first=true;
		while(len>0)
		{
			long curPos=positions[currentBufferIndex];

			if (currentPosition>=curPos+maxBufferSize)
			{
				curPos=positions[currentBufferIndex]=currentPosition;
				if (first) {
					in.seek(currentPosition);
					first=false;
				}
				int nb=in.read(currentBuffer, 0, Math.min(maxBufferSize, len));
				if (nb<len)
					return nb+res;
			}
			int bufPos=(int)(currentPosition-curPos);
			int copyLen=Math.min(len, maxBufferSize-bufPos);
			System.arraycopy(currentBuffer, bufPos, b, off, copyLen);
			len-=copyLen;
			off+=copyLen;
			res+=copyLen;
			currentPosition+=copyLen;
		}
		return res;
	}


	@Override
	public long skip(long n) throws IOException {
		long oldPos=currentPosition;
		currentPosition=Math.min(currentPosition+n, in.length());
		n=currentPosition-oldPos;
		chooseBuffer(currentPosition);
		return n;
	}

	@Override
	public int available() throws IOException {
		in.seek(currentPosition);
		return in.available();
	}

	@Override
	public void close() throws IOException {
		in.close();
	}

}

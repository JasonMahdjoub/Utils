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

import java.io.File;
import java.io.IOException;

/**
 * @author Jason Mahdjoub
 * @version 1.1
 * @since Utils 4.6.0
 */
public class RandomCacheFileOutputStream extends RandomOutputStream{
	private final RandomCacheFileCenter randomCacheFileCenter;
	private RandomOutputStream out;
	private final File fileName;
	private final RandomFileOutputStream.AccessMode accessMode;
	private boolean fileUsed;
	private final int maxBufferSize, maxBuffersNumber;
	private final boolean removeFileWhenClosed;
	private boolean closed=false;
	private RandomInputStream in=null;
	RandomCacheFileOutputStream(RandomCacheFileCenter randomCacheFileCenter, File fileName, boolean removeFileWhenClosed, RandomFileOutputStream.AccessMode accessMode,int maxBufferSize, int maxBuffersNumber)
	{
		this.randomCacheFileCenter=randomCacheFileCenter;
		this.out=new RandomByteArrayOutputStream();
		this.fileName=fileName;
		this.fileUsed=false;
		this.accessMode=accessMode;
		this.maxBufferSize=maxBufferSize;
		this.maxBuffersNumber=maxBuffersNumber;
		this.removeFileWhenClosed=removeFileWhenClosed;
	}

	public void forceWritingMemoryCacheToFile() throws IOException {
		if (fileUsed)
			return;

		RandomOutputStream fout=new RandomFileOutputStream(fileName, accessMode);
		if (maxBufferSize>0)
			fout=new BufferedRandomOutputStream(fout, maxBufferSize, maxBuffersNumber);

		fout.write(((RandomByteArrayOutputStream)out).getBytes());
		randomCacheFileCenter.releaseDataFromMemory(out.length());
		out=fout;
		if (in!=null)
			in=out.getRandomInputStream();
		fileUsed=true;
	}


	@Override
	public long length() throws IOException {
		return out.length();
	}

	@Override
	public void setLength(long newLength) throws IOException {
		if (closed)
			throw new IOException("Stream closed !");
		if (!fileUsed) {
			long dataQuantity = newLength-out.length();
			if (dataQuantity!=0) {
				if (dataQuantity < 0) {
					randomCacheFileCenter.releaseDataFromMemory(-dataQuantity);
				} else if (!randomCacheFileCenter.tryToAddNewDataIntoMemory(dataQuantity)) {
					forceWritingMemoryCacheToFile();
				}
				out.setLength(newLength);
			}
		}
		else
			out.setLength(newLength);


	}

	@Override
	public void seek(long _pos) throws IOException {
		if (closed)
			throw new IOException("Stream closed !");
		out.seek(_pos);
	}

	@Override
	public long currentPosition() throws IOException {
		return out.currentPosition();
	}

	@Override
	public boolean isClosed() {
		return closed;
	}

	@Override
	protected RandomInputStream getRandomInputStreamImpl() throws IOException {
		if (closed)
			throw new IOException("Stream closed !");
		if (in==null)
			in=out.getRandomInputStream();
		return new RandomInputStream() {
			public long length() throws IOException {
				return in.length();
			}

			public void seek(long _pos) throws IOException {
				in.seek(_pos);
			}

			public long currentPosition() throws IOException {
				return in.currentPosition();
			}

			public void mark(int readlimit) {
				in.mark(readlimit);
			}

			public boolean markSupported() {
				return in.markSupported();
			}

			public void reset() throws IOException {
				in.reset();
			}

			public boolean isClosed() {
				return in.isClosed();
			}

			public void readFully(byte[] tab, int off, int len) throws IOException {
				in.readFully(tab, off, len);
			}

			public int available() throws IOException {
				return in.available();
			}

			public void skipNBytes(long n) throws IOException {
				in.skipNBytes(n);
			}

			public void readFully(RandomOutputStream outputStream, long length) throws IOException {
				in.readFully(outputStream, length);
			}

			public void readFully(RandomOutputStream outputStream) throws IOException {
				in.readFully(outputStream);
			}

			public void close() throws IOException {
				in.close();
			}

			public long skip(long n) throws IOException {
				return in.skip(n);
			}

			public byte[] readNBytes(int len) throws IOException {
				return in.readNBytes(len);
			}


			public int read() throws IOException {
				return in.read();
			}

			public int read(byte[] b) throws IOException {
				return in.read(b);
			}

			public int read(byte[] b, int off, int len) throws IOException {
				return in.read(b, off, len);
			}

			public String readLine() throws IOException {
				return in.readLine();
			}
		};
	}

	@Override
	public void write(int b) throws IOException {
		if (closed)
			throw new IOException("Stream closed !");
		if (!fileUsed && !randomCacheFileCenter.tryToAddNewDataIntoMemory(1))
			forceWritingMemoryCacheToFile();
		out.write(b);
	}

	@Override
	public void write(byte[] b, int off, int len) throws IOException {
		if (closed)
			throw new IOException("Stream closed !");
		RandomInputStream.checkLimits(b, off, len);
		if (!fileUsed && !randomCacheFileCenter.tryToAddNewDataIntoMemory(len))
			forceWritingMemoryCacheToFile();
		out.write(b, off, len);
	}

	@Override
	public void close() throws IOException {
		if (closed)
			return;
		try {
			if (!fileUsed) {
				randomCacheFileCenter.releaseDataFromMemory(out.length());
			}
			if (!out.isClosed())
				out.close();
			if (fileUsed && removeFileWhenClosed)
				//noinspection ResultOfMethodCallIgnored
				fileName.delete();
		}
		finally {
			closed=true;
		}
	}

	@Override
	public void flush() throws IOException {
		if (closed)
			throw new IOException("Stream closed !");
		out.flush();
	}

	@SuppressWarnings("deprecation")
	@Override
	public void finalize()
	{
		if (!isClosed()) {
			try {
				close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}
}

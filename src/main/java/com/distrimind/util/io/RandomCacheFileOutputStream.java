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

import com.distrimind.util.Cleanable;
import com.distrimind.util.FileTools;

import java.io.File;
import java.io.IOException;

/**
 * @author Jason Mahdjoub
 * @version 1.1
 * @since Utils 4.6.0
 */
@SuppressWarnings("NullableProblems")
public class RandomCacheFileOutputStream extends RandomOutputStream implements Cleanable {



	private final RandomFileOutputStream.AccessMode accessMode;

	private final int maxBufferSize, maxBuffersNumber;


	private RandomInputStream in=null;
	private final Finalizer finalizer;

	private static final class Finalizer extends Cleaner
	{
		private boolean closed=false;
		private boolean fileUsed;
		private final RandomCacheFileCenter randomCacheFileCenter;
		private final boolean removeFileWhenClosed;
		private final File fileName;
		private RandomOutputStream out;

		private Finalizer(RandomCacheFileCenter randomCacheFileCenter, boolean removeFileWhenClosed, File fileName) {
			this.randomCacheFileCenter = randomCacheFileCenter;
			this.removeFileWhenClosed = removeFileWhenClosed;
			this.fileName = fileName;
		}

		@Override
		protected void performCleanup() {
			if (!closed) {
				try {
					close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
		}
		private void close() throws IOException {
			if (closed)
				return;
			try {
				if (!fileUsed) {
					randomCacheFileCenter.releaseDataFromMemory(out.length());
				}
				if (!out.isClosed())
					out.close();
				if (fileUsed && removeFileWhenClosed) {
					if (fileName.exists()) {
						if (!fileName.delete())
							throw new IOException("Impossible to delete file " + fileName);
					}
				}
			}
			finally {
				closed=true;
			}
		}
	}

	RandomCacheFileOutputStream(RandomCacheFileCenter randomCacheFileCenter, File fileName, boolean removeFileWhenClosed, RandomFileOutputStream.AccessMode accessMode,int maxBufferSize, int maxBuffersNumber) {
		this.finalizer=new Finalizer(randomCacheFileCenter, removeFileWhenClosed, fileName);

		this.registerCleaner(finalizer);
		this.finalizer.out=new RandomByteArrayOutputStream();
		this.finalizer.fileUsed=false;
		this.accessMode=accessMode;
		this.maxBufferSize=maxBufferSize;
		this.maxBuffersNumber=maxBuffersNumber;
	}

	public void forceWritingMemoryCacheToFile() throws IOException {
		if (finalizer.fileUsed)
			return;

		RandomOutputStream fout=new RandomFileOutputStream(finalizer.fileName, accessMode);
		if (maxBufferSize>0)
			fout=new BufferedRandomOutputStream(fout, maxBufferSize, maxBuffersNumber);
		finalizer.out.flush();
		RandomByteArrayOutputStream baos=(RandomByteArrayOutputStream)finalizer.out;
		assert fout.length()==0;
		assert fout.currentPosition()==0;
		long cp=finalizer.out.currentPosition();
		assert cp>=0;
		fout.write(baos.bytes, 0, baos.length);
		finalizer.randomCacheFileCenter.releaseDataFromMemory(baos.length);
		fout.seek(cp);
		if (in!=null) {
			cp=in.currentPosition();
			in = fout.getRandomInputStream();
			in.seek(cp);
		}
		finalizer.out.close();
		finalizer.out=fout;

		finalizer.fileUsed=true;
	}



	@Override
	public long length() throws IOException {
		return finalizer.out.length();
	}

	@Override
	public void setLength(long newLength) throws IOException {
		if (finalizer.closed)
			throw new IOException("Stream closed !");
		if (newLength<0)
			throw new IllegalArgumentException();
		if (finalizer.fileUsed) {
			finalizer.out.setLength(newLength);
		}
		else{

			long dataQuantity = newLength-finalizer.out.length();
			if (dataQuantity!=0) {
				if (dataQuantity < 0) {
					finalizer.randomCacheFileCenter.releaseDataFromMemory(-dataQuantity);
				} else if (!finalizer.randomCacheFileCenter.tryToAddNewDataIntoMemory(dataQuantity)) {
					forceWritingMemoryCacheToFile();
				}
				finalizer.out.setLength(newLength);
			}
		}


	}

	@Override
	public void seek(long _pos) throws IOException {
		if (finalizer.closed)
			throw new IOException("Stream closed !");
		finalizer.out.seek(_pos);
	}

	@Override
	public long currentPosition() throws IOException {
		return finalizer.out.currentPosition();
	}

	@Override
	public boolean isClosed() {
		return finalizer.closed;
	}



	@Override
	protected RandomInputStream getRandomInputStreamImpl() throws IOException {
		if (finalizer.closed)
			throw new IOException("Stream closed !");
		if (in==null)
			in=finalizer.out.getRandomInputStream();
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

			public void mark(int readLimit) {
				in.mark(readLimit);
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
				RandomCacheFileOutputStream.this.close();
				if (!in.isClosed())
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

	private void tryToAddNewDataIntoMemory(int len) throws IOException {
		if (finalizer.fileUsed)
			return;
		long s=((long)len)-(finalizer.out.length()-finalizer.out.currentPosition());
		if (s>0 && !finalizer.randomCacheFileCenter.tryToAddNewDataIntoMemory(s))
			forceWritingMemoryCacheToFile();
	}

	@Override
	public void write(int b) throws IOException {
		if (finalizer.closed)
			throw new IOException("Stream closed !");
		tryToAddNewDataIntoMemory(1);
		finalizer.out.write(b);
	}

	@Override
	public void write(byte[] b, int off, int len) throws IOException {
		if (finalizer.closed)
			throw new IOException("Stream closed !");
		tryToAddNewDataIntoMemory(len);
		finalizer.out.write(b, off, len);
	}

	@Override
	public void close() throws IOException {
		finalizer.close();
	}

	@Override
	public void flush() throws IOException {
		if (finalizer.closed)
			throw new IOException("Stream closed !");
		finalizer.out.flush();
	}


	public void moveToFileAndCloseStream(File file) throws IOException {
		moveToFileAndCloseStream(file, false);
	}
	public void moveToFileAndCloseStream(File file, boolean checkDestinationRecursive) throws IOException {
		if (isClosed())
			throw new IOException("Stream closed !");
		if (finalizer.fileUsed) {
			finalizer.out.close();
			FileTools.move(finalizer.fileName, file, checkDestinationRecursive);
		} else {
			getRandomInputStream().transferTo(new RandomFileOutputStream(file));
		}
		close();
	}
}

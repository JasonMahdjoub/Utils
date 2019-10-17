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
 * @version 1.0
 * @since MaDKitLanEdition 4.6.0
 */
public class RandomCacheFileOutputStream extends RandomOutputStream{
	private final RandomCacheFileCenter randomCacheFileCenter;
	private RandomOutputStream out;
	private final File fileName;
	private final RandomFileOutputStream.AccessMode accessMode;
	private boolean fileUsed;
	private final int maxBufferSize, maxBuffersNumber;
	RandomCacheFileOutputStream(RandomCacheFileCenter randomCacheFileCenter, File fileName, RandomFileOutputStream.AccessMode accessMode,int maxBufferSize, int maxBuffersNumber)
	{
		this.randomCacheFileCenter=randomCacheFileCenter;
		this.out=new RandomByteArrayOutputStream();
		this.fileName=fileName;
		this.fileUsed=false;
		this.accessMode=accessMode;
		this.maxBufferSize=maxBufferSize;
		this.maxBuffersNumber=maxBuffersNumber;
	}

	public void forceWritingMemoryCacheToFile() throws IOException {
		if (fileUsed)
			return;

		RandomOutputStream fout=new RandomFileOutputStream(fileName, accessMode);;
		if (maxBufferSize>0)
			fout=new BufferedRandomOutputStream(fout, maxBufferSize, maxBuffersNumber);

		fout.write(((RandomByteArrayOutputStream)out).getBytes());
		randomCacheFileCenter.releaseDataFromMemory(out.length());
		out=fout;
		fileUsed=true;
	}


	@Override
	public long length() throws IOException {
		return out.length();
	}

	@Override
	public void setLength(long newLength) throws IOException {
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
		out.seek(_pos);
	}

	@Override
	public long currentPosition() throws IOException {
		return out.currentPosition();
	}

	@Override
	public boolean isClosed() {
		return out.isClosed();
	}

	@Override
	protected RandomInputStream getRandomInputStreamImpl() throws IOException {
		return out.getRandomInputStream();
	}

	@Override
	public void write(int b) throws IOException {
		if (!fileUsed && !randomCacheFileCenter.tryToAddNewDataIntoMemory(1))
			forceWritingMemoryCacheToFile();
		out.write(b);
	}

	@Override
	public void write(byte[] b, int off, int len) throws IOException {
		if (len<0)
			throw new IllegalArgumentException();
		if (!fileUsed && !randomCacheFileCenter.tryToAddNewDataIntoMemory(len))
			forceWritingMemoryCacheToFile();
		out.write(b, off, len);
	}

	@Override
	public void close() throws IOException {
		if (out.isClosed())
			return;
		if (!fileUsed)
		{
			randomCacheFileCenter.releaseDataFromMemory(out.length());
		}
		out.close();
	}

	@Override
	public void flush() throws IOException {
		out.flush();
	}

	@SuppressWarnings("deprecation")
	@Override
	public void finalize()
	{
		if (!isClosed()) {
			try {
				flush();
				close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}
}

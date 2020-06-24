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
 * @version 1.2
 * @since Utils 4.6.0
 */
public class RandomCacheFileCenter {
	private volatile long maxMemoryUsedToStoreDataIntoMemoryInsteadOfFiles;
	private long memoryUsedToStoreDataIntoMemoryInsteadOfFiles;
	private static final String prefixTmpFileName="DistriMindCacheFileCenter";
	private static final String suffixTmpFileName="data";
	private static final RandomCacheFileCenter singleton=new RandomCacheFileCenter();


	private RandomCacheFileCenter() {
		this(getContextualizedMaxMemorySize());
	}

	private static long getContextualizedMaxMemorySize()
	{
		double mm=Runtime.getRuntime().maxMemory();
		if (mm<128.0)
			return 8;
		else
		{
			return (long)(0.0074*mm+7.0551);
		}
	}

	public static RandomCacheFileCenter getSingleton()
	{
		return singleton;
	}

	public RandomCacheFileCenter(long maxMemoryUsedToStoreDataIntoMemoryInsteadOfFiles) {
		this.maxMemoryUsedToStoreDataIntoMemoryInsteadOfFiles=maxMemoryUsedToStoreDataIntoMemoryInsteadOfFiles;
		this.memoryUsedToStoreDataIntoMemoryInsteadOfFiles=0;
	}
	public RandomCacheFileOutputStream getNewRandomCacheFileOutputStream() throws IOException {
		return getNewRandomCacheFileOutputStream(true);
	}

	public void setMaxMemoryUsedToStoreDataIntoMemoryInsteadOfFiles(long maxMemoryUsedToStoreDataIntoMemoryInsteadOfFiles) {
		this.maxMemoryUsedToStoreDataIntoMemoryInsteadOfFiles = maxMemoryUsedToStoreDataIntoMemoryInsteadOfFiles;
	}

	public RandomCacheFileOutputStream getNewRandomCacheFileOutputStream(boolean removeFileWhenClosingStream) throws IOException {
		return getNewRandomCacheFileOutputStream(File.createTempFile(prefixTmpFileName, suffixTmpFileName), removeFileWhenClosingStream, RandomFileOutputStream.AccessMode.READ_AND_WRITE);
	}
	public RandomCacheFileOutputStream getNewRandomCacheFileOutputStream(File fileName, boolean removeFileWhenClosingStream) throws IOException {
		return getNewRandomCacheFileOutputStream(fileName, removeFileWhenClosingStream, RandomFileOutputStream.AccessMode.READ_AND_WRITE);
	}
	public RandomCacheFileOutputStream getNewRandomCacheFileOutputStream(File fileName, boolean removeFileWhenClosingStream, RandomFileOutputStream.AccessMode accessMode) throws IOException {
		return new RandomCacheFileOutputStream(this, fileName, removeFileWhenClosingStream, accessMode, -1,0);
	}

	public RandomCacheFileOutputStream getNewBufferedRandomCacheFileOutputStream() throws IOException {
		return getNewBufferedRandomCacheFileOutputStream(true);
	}
	public RandomCacheFileOutputStream getNewBufferedRandomCacheFileOutputStream(boolean removeFileWhenClosingStream) throws IOException {
		return getNewBufferedRandomCacheFileOutputStream(removeFileWhenClosingStream, RandomFileOutputStream.AccessMode.READ_AND_WRITE);
	}

	public RandomCacheFileOutputStream getNewBufferedRandomCacheFileOutputStream(boolean removeFileWhenClosingStream, RandomFileOutputStream.AccessMode accessMode) throws IOException {
		return getNewBufferedRandomCacheFileOutputStream(removeFileWhenClosingStream, accessMode, BufferedRandomInputStream.DEFAULT_MAX_BUFFER_SIZE);
	}

	public RandomCacheFileOutputStream getNewBufferedRandomCacheFileOutputStream(boolean removeFileWhenClosingStream, RandomFileOutputStream.AccessMode accessMode,  int maxBufferSize) throws IOException {
		return getNewBufferedRandomCacheFileOutputStream(removeFileWhenClosingStream, accessMode, maxBufferSize, BufferedRandomInputStream.DEFAULT_MAX_BUFFERS_NUMBER);
	}
	public RandomCacheFileOutputStream getNewBufferedRandomCacheFileOutputStream(boolean removeFileWhenClosingStream, RandomFileOutputStream.AccessMode accessMode,  int maxBufferSize, int maxBuffersNumber) throws IOException {
		return getNewBufferedRandomCacheFileOutputStream(File.createTempFile(prefixTmpFileName, suffixTmpFileName), removeFileWhenClosingStream, accessMode, maxBufferSize, maxBuffersNumber);
	}

	public RandomCacheFileOutputStream getNewBufferedRandomCacheFileOutputStream(File fileName, boolean removeFileWhenClosingStream) throws IOException {
		return getNewBufferedRandomCacheFileOutputStream(fileName, removeFileWhenClosingStream, BufferedRandomInputStream.DEFAULT_MAX_BUFFER_SIZE);
	}
	public RandomCacheFileOutputStream getNewBufferedRandomCacheFileOutputStream(File fileName, boolean removeFileWhenClosingStream, RandomFileOutputStream.AccessMode accessMode) throws IOException {
		return getNewBufferedRandomCacheFileOutputStream(fileName, removeFileWhenClosingStream, accessMode, BufferedRandomInputStream.DEFAULT_MAX_BUFFER_SIZE);
	}
	public RandomCacheFileOutputStream getNewBufferedRandomCacheFileOutputStream(File fileName,  boolean removeFileWhenClosingStream, int maxBufferSize) throws IOException {
		return getNewBufferedRandomCacheFileOutputStream(fileName, removeFileWhenClosingStream, RandomFileOutputStream.AccessMode.READ_AND_WRITE, maxBufferSize, BufferedRandomInputStream.DEFAULT_MAX_BUFFERS_NUMBER);
	}
	public RandomCacheFileOutputStream getNewBufferedRandomCacheFileOutputStream(File fileName, boolean removeFileWhenClosingStream, RandomFileOutputStream.AccessMode accessMode,  int maxBufferSize) throws IOException {
		return getNewBufferedRandomCacheFileOutputStream(fileName, removeFileWhenClosingStream, accessMode, maxBufferSize, BufferedRandomInputStream.DEFAULT_MAX_BUFFERS_NUMBER);
	}

	public RandomCacheFileOutputStream getNewBufferedRandomCacheFileOutputStream(File fileName, boolean removeFileWhenClosingStream, RandomFileOutputStream.AccessMode accessMode,  int maxBufferSize, int maxBuffersNumber) throws IOException {
		return new RandomCacheFileOutputStream(this, fileName, removeFileWhenClosingStream, accessMode, maxBufferSize, maxBuffersNumber);
	}

	@SuppressWarnings("BooleanMethodIsAlwaysInverted")
	boolean tryToAddNewDataIntoMemory(long numberOfBytes )
	{
		synchronized (this)
		{
			this.memoryUsedToStoreDataIntoMemoryInsteadOfFiles+=numberOfBytes;
			if (this.memoryUsedToStoreDataIntoMemoryInsteadOfFiles>maxMemoryUsedToStoreDataIntoMemoryInsteadOfFiles) {
				this.memoryUsedToStoreDataIntoMemoryInsteadOfFiles-=numberOfBytes;
				return false;
			}
			return true;
		}
	}

	void releaseDataFromMemory(long numberOfBytes )
	{
		this.memoryUsedToStoreDataIntoMemoryInsteadOfFiles-=numberOfBytes;
		if (this.memoryUsedToStoreDataIntoMemoryInsteadOfFiles<0) {
			this.memoryUsedToStoreDataIntoMemoryInsteadOfFiles = 0;
			throw new InternalError();
		}
	}



}

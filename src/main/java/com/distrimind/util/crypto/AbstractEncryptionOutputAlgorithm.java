/*
Copyright or © or Corp. Jason Mahdjoub (04/02/2016)

jason.mahdjoub@distri-mind.fr

This software (Utils) is a computer program whose purpose is to give several kind of tools for developers 
(ciphers, XML readers, decentralized id generators, etc.).

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
package com.distrimind.util.crypto;

import com.distrimind.util.AutoZeroizable;
import com.distrimind.util.Cleanable;
import com.distrimind.util.io.*;

import javax.crypto.Cipher;
import java.io.IOException;
import java.util.Arrays;

/**
 * 
 * @author Jason Mahdjoub
 * @version 5.0
 * @since Utils 1.5
 */
public abstract class AbstractEncryptionOutputAlgorithm implements AutoZeroizable, IClientServer {
	final static int BUFFER_SIZE = 32*1024;

	protected static class Finalizer extends Cleaner
	{
		private byte[] buffer1=null;
		private byte[] buffer2=null;
		private byte[] currentBuffer=null;

		protected Finalizer(Cleanable cleanable) {
			super(cleanable);
		}

		@Override
		protected void performCleanup() {
			if (buffer1!=null) {
				Arrays.fill(buffer1, (byte) 0);
				buffer1 = null;
			}
			if (buffer2!=null) {
				Arrays.fill(buffer2, (byte) 0);
				buffer2 = null;
			}
			currentBuffer=null;
		}
		void initBuffers(int size)
		{
			buffer1=new byte[size];
			buffer2=new byte[size];
			currentBuffer=null;
		}
		byte[] switchBuffer()
		{
			if (currentBuffer==buffer1)
				return currentBuffer=buffer2;
			else
				return currentBuffer=buffer1;
		}
		int getBufferSize()
		{
			return buffer1.length;
		}
		byte[] switchBuffer(int size)
		{
			if (currentBuffer==buffer1) {

				if (buffer2.length<size) {
					currentBuffer = new byte[size];
					Arrays.fill(buffer2, (byte) 0);
					buffer2=currentBuffer;
				}
				else
					currentBuffer = buffer2;
			}
			else {
				if (buffer1.length<size) {
					currentBuffer = new byte[size];
					Arrays.fill(buffer1, (byte) 0);
					buffer1=currentBuffer;
				}
				else
					currentBuffer = buffer1;
			}
			return currentBuffer;
		}
	}
	protected final Finalizer finalizer;
	protected final AbstractCipher cipher;


	protected int bufferInSize;
	//protected byte[] bufferOut;
	protected int maxPlainTextSizeForEncoding=-1;
	protected int maxEncryptedPartLength;
	private final byte[] one=new byte[1];

	private long previousAskedLengthForEncryption=-1;
	private long previousOutputSizeAfterEncryption;
	private int IvAndSecretKeySizeInBytesWithoutExternalCounter;

	protected boolean useDerivedSecretKeys()
	{
		return false;
	}


	


	public byte getMaxExternalCounterLength()
	{
		return 0;
	}

	protected AbstractEncryptionOutputAlgorithm()
	{
		super();
		cipher=null;
		this.finalizer=new Finalizer(this);

	}

	protected AbstractEncryptionOutputAlgorithm(AbstractCipher cipher, int ivSizeBytes) {
		if (cipher == null)
			throw new NullPointerException("cipher");
		this.cipher = cipher;
		this.finalizer=new Finalizer(this);
	}

	protected void initBufferAllocatorArgs() throws IOException {
		int bol=(int) getOutputSizeAfterEncryption(bufferInSize =BUFFER_SIZE);
		if (bol>BUFFER_SIZE*2)
		{
			bol=(int) getOutputSizeAfterEncryption(bufferInSize =4096);
		}
		zeroize();
		finalizer.initBuffers(bol);
	}
	

	
	public byte[] encode(byte[] bytes) throws IOException{
		return encode(bytes, 0, bytes.length);
	}
	public byte[] encode(byte[] bytes, byte[] associatedData) throws IOException{
		return encode(bytes, 0, bytes.length, associatedData, 0, associatedData==null?0:associatedData.length, (byte[])null);
	}
	public byte[] encode(byte[] bytes, byte[] associatedData, byte[] externalCounter) throws IOException{
		return encode(bytes, 0, bytes.length, associatedData, 0, associatedData==null?0:associatedData.length, externalCounter);
	}

	public byte[] encode(byte[] bytes, int off, int len) throws IOException{
		return encode(bytes, off, len, null, 0, 0);
	}
	
	public byte[] encode(byte[] bytes, int off, int len, byte[] associatedData, int offAD, int lenAD) throws IOException{
		return encode(bytes, off, len, associatedData, offAD, lenAD, (byte[])null);
	}
	public byte[] encode(byte[] bytes, int off, int len, byte[] associatedData, int offAD, int lenAD, byte[] externalCounter) throws IOException{
		try (RandomByteArrayOutputStream baos = new RandomByteArrayOutputStream()) {
			encode(bytes, off, len, associatedData, offAD, lenAD, baos, externalCounter);
			return baos.getBytes();
		}
	}
	public void encode(byte[] bytes, int off, int len, RandomOutputStream os) throws IOException{
		encode(bytes, off, len, null,0, 0, os);
	}
	public void encode(byte[] bytes, int off, int len, byte[] associatedData, int offAD, int lenAD, RandomOutputStream os) throws IOException
	{
		encode(bytes, off, len, associatedData, offAD, lenAD, os, null);
	}



	protected abstract void initCipherForEncryptionWithIvAndCounter(AbstractCipher cipher, AbstractWrappedIVs<?, ?> wrappedIVAndSecretKey, int counter) throws IOException;


	public void encode(byte[] bytes, int off, int len, byte[] associatedData, int offAD, int lenAD, RandomOutputStream os, byte[] externalCounter) throws IOException{
		RandomInputStream ris=new RandomByteArrayInputStream(bytes);
		try {
			if (len != bytes.length || off!=0)
				ris = new LimitedRandomInputStream(ris, off, len);
			encode(ris, associatedData, offAD, lenAD, os, externalCounter);
		}
		finally {
			ris.close();
		}
	}
	public void encode(RandomInputStream is, RandomOutputStream os) throws IOException
	{
		encode(is, null, 0, 0, os);
	}
	public void encode(RandomInputStream is, byte[] associatedData, RandomOutputStream os) throws IOException
	{
		encode(is, associatedData, 0, associatedData==null?0:associatedData.length, os);
	}
	public void encode(RandomInputStream is, byte[] associatedData, int offAD, int lenAD, RandomOutputStream os) throws IOException{
		encode(is, associatedData, offAD, lenAD, os, null);
	}

	public void encode(RandomInputStream is, byte[] associatedData, int offAD, int lenAD, RandomOutputStream os, byte[] externalCounter) throws IOException {

		try(RandomOutputStream cos = getCipherOutputStreamForEncryption(os, false, associatedData, offAD, lenAD, externalCounter))
		{
			is.transferTo(cos);
		}
	}

	protected static void checkLimits(byte[] b, int off, int len)
	{
		if (b==null)
			throw new NullPointerException();
		if ((off | len) < 0 || len > b.length - off)
			throw new IndexOutOfBoundsException();
	}
	protected abstract int getCounterStepInBytes();

	public abstract boolean supportRandomEncryptionAndRandomDecryption();

	public RandomOutputStream getCipherOutputStreamForEncryption(final RandomOutputStream os, boolean closeOutputStreamWhenClosingCipherOutputStream) throws IOException
	{
		return getCipherOutputStreamForEncryption(os, closeOutputStreamWhenClosingCipherOutputStream, null, 0,0, null);
	}
	public RandomOutputStream getCipherOutputStreamForEncryption(final RandomOutputStream os, boolean closeOutputStreamWhenClosingCipherOutputStream, final byte[] associatedData, final int offAD, final int lenAD) throws IOException
	{
		return getCipherOutputStreamForEncryption(os, closeOutputStreamWhenClosingCipherOutputStream, associatedData, offAD, lenAD, null);
	}
	public RandomOutputStream getCipherOutputStreamForEncryption(final RandomOutputStream os, boolean closeOutputStreamWhenClosingCipherOutputStream, byte[] externalCounter) throws IOException
	{
		return getCipherOutputStreamForEncryption(os, closeOutputStreamWhenClosingCipherOutputStream, null, 0,0, externalCounter);
	}

	public RandomOutputStream getCipherOutputStreamForEncryption(final RandomOutputStream os, boolean closeOutputStreamWhenClosingCipherOutputStream, final byte[] associatedData, final int offAD, final int lenAD, final byte[] externalCounter) throws
			IOException{
		return getCipherOutputStreamForEncryption(os, closeOutputStreamWhenClosingCipherOutputStream, associatedData, offAD, lenAD, externalCounter,  false);
	}
	RandomOutputStream getCipherOutputStreamForEncryption(final RandomOutputStream os, boolean closeOutputStreamWhenClosingCipherOutputStream, final byte[] associatedData, final int offAD, final int lenAD, final byte[] externalCounter, boolean replaceMainKeyWhenClosingStream) throws
			IOException{
		return getCipherOutputStreamForEncryption(os, closeOutputStreamWhenClosingCipherOutputStream, associatedData, offAD, lenAD, externalCounter, null, replaceMainKeyWhenClosingStream);
	}
	protected abstract CPUUsageAsDecoyOutputStream<CommonCipherOutputStream> getCPUUsageAsDecoyOutputStream(CommonCipherOutputStream os) throws IOException;

	@SuppressWarnings({"unchecked", "SameParameterValue"})
	static void set(RandomOutputStream cipherOutputStream, RandomOutputStream os, AbstractWrappedIVs<?, ?> manualIvsAndSecretKeys, byte[] externalCounter, byte[] associatedData, int offAD, int lenAD, boolean closeOutputStreamWhenClosingCipherOutputStream, boolean replaceMainKeyWhenClosingStream) throws IOException {
		if (cipherOutputStream instanceof CPUUsageAsDecoyOutputStream) {
			CPUUsageAsDecoyOutputStream<CommonCipherOutputStream> o=((CPUUsageAsDecoyOutputStream<CommonCipherOutputStream>) cipherOutputStream);
			o.reset();
			o.getDestinationRandomOutputStream()
					.set(os, manualIvsAndSecretKeys, externalCounter, associatedData, offAD, lenAD, closeOutputStreamWhenClosingCipherOutputStream, replaceMainKeyWhenClosingStream);
		}
		else
			((AbstractEncryptionOutputAlgorithm.CommonCipherOutputStream)cipherOutputStream)
					.set(os, manualIvsAndSecretKeys, externalCounter, associatedData, offAD, lenAD, closeOutputStreamWhenClosingCipherOutputStream, replaceMainKeyWhenClosingStream);
	}
	protected void replaceMainKeyByLastDerivedSecretKey(AbstractWrappedIVs<?, ?> wrappedIVAndSecretKey) throws IOException {

	}
	protected class CommonCipherOutputStream extends RandomOutputStream
	{
		long length;
		long currentPos;
		boolean closed;
		private boolean doFinal;
		boolean supportRandomAccess;

		RandomOutputStream os;
		private AbstractWrappedIVs<?, ?> manualIvsAndSecretKeys;
		private byte[] externalCounter;
		private byte[] associatedData;
		private int offAD, lenAD;
		private boolean closeOutputStreamWhenClosingCipherOutputStream;

		private boolean initPossible;

		private AbstractWrappedIVs<?, ?> wrappedIVAndSecretKey;
		private boolean replaceMainKeyWhenClosingStream;



		CommonCipherOutputStream(RandomOutputStream os, AbstractWrappedIVs<?, ?> manualIvsAndSecretKeys, byte[] externalCounter, byte[] associatedData, int offAD, int lenAD, boolean closeOutputStreamWhenClosingCipherOutputStream, boolean replaceMainKeyWhenClosingStream) throws IOException {
			set(os, manualIvsAndSecretKeys, externalCounter, associatedData, offAD, lenAD, closeOutputStreamWhenClosingCipherOutputStream, replaceMainKeyWhenClosingStream);
		}

		protected void set(RandomOutputStream os, AbstractWrappedIVs<?, ?> manualIvsAndSecretKeys, byte[] externalCounter, byte[] associatedData, int offAD, int lenAD, boolean closeOutputStreamWhenClosingCipherOutputStream, boolean replaceMainKeyWhenClosingStream) throws IOException {
			checkKeysNotCleaned();

			length=0;
			currentPos=0;
			closed=false;
			doFinal=false;
			initPossible=true;
			this.replaceMainKeyWhenClosingStream=replaceMainKeyWhenClosingStream;
			supportRandomAccess=supportRandomEncryptionAndRandomDecryption();

			this.os = os;
			this.manualIvsAndSecretKeys = manualIvsAndSecretKeys;
			this.externalCounter = externalCounter;
			this.associatedData = associatedData;
			this.offAD = offAD;
			this.lenAD = lenAD;
			this.closeOutputStreamWhenClosingCipherOutputStream = closeOutputStreamWhenClosingCipherOutputStream;
			wrappedIVAndSecretKey= getWrappedIVAndSecretKeyInstance();
			if (os.currentPosition()!=0)
				os.seek(0);
		}


		private void checkDoFinal(boolean force) throws IOException {
			if (doFinal && (currentPos%maxPlainTextSizeForEncoding==0 || force))
			{
				if (cipher.getClass()==BCMcElieceCipher.class)
				{
					byte[] res=cipher.doFinal();
					if (res!=null && res.length>0)
						os.write(res);
				}
				else {
					byte[] buffer=finalizer.switchBuffer();
					int s;
					try {
						 s = cipher.doFinal(buffer, 0);

					}
					catch (IOException e)
					{
						finalizer.switchBuffer();
						throw e;
					}
					if (s > 0)
						os.write(buffer, 0, s);
					else
						finalizer.switchBuffer();
				}
				doFinal = false;
			}
		}

		private void init(long round, RandomOutputStream os) throws IOException {
			if (initPossible) {
				if (wrappedIVAndSecretKey != null) {
					assert includeIV();
					if (manualIvsAndSecretKeys != null) {
						manualIvsAndSecretKeys.setCurrentIV(round, os, useExternalCounter() ? externalCounter : null);
						initCipherForEncryptionWithIvAndCounter(cipher, manualIvsAndSecretKeys, 0);

					} else {
						wrappedIVAndSecretKey.generateNewElement(round, os, useExternalCounter() ? externalCounter : null);
						initCipherForEncryptionWithIvAndCounter(cipher, wrappedIVAndSecretKey, 0);
					}

				} else {
					assert !includeIV();
					initCipherForEncryptionWithNullIV(cipher);
				}

				if (associatedData != null && lenAD > 0)
					cipher.updateAAD(associatedData, offAD, lenAD);
				initPossible = false;
			}
		}

		private long checkInit() throws IOException {
			long mod=currentPos % maxPlainTextSizeForEncoding;
			if (mod == 0) {
				long round=currentPos/ maxPlainTextSizeForEncoding;
				checkDoFinal(false);
				init(round,os);
			}
			return (int) (maxPlainTextSizeForEncoding-mod);
		}
		@Override
		public long length() {
			return length;
		}

		@Override
		public void write(byte[] b, int off, int len) throws IOException {
			if (closed)
				throw new IOException("Stream closed");
			checkLimits(b, off, len);
			if (len==0)
				return;

			while (len>0) {
				long l=checkInit();
				int s=(int)Math.min(len, l);
				assert s>0;
				byte[] buffer;
				if (s> bufferInSize) {
					int outLen = cipher.getOutputSize(s);
					buffer=finalizer.switchBuffer(outLen);
				}
				else
					buffer=finalizer.switchBuffer();
				int w;
				try {
					w = cipher.update(b, off, s, buffer, 0);
				}
				catch (IOException e)
				{
					finalizer.switchBuffer();
					throw e;
				}
				doFinal=true;
				initPossible=true;
				currentPos+=s;
				if (w>0) {
					os.write(buffer, 0, w);
				}
				else
					finalizer.switchBuffer();

				len-=s;
				off+=s;

				checkDoFinal(false);
			}
			length=Math.max(length, currentPos);
		}
		@Override
		public void write(int b) throws IOException {
			if (closed)
				throw new IOException("Stream closed");

			checkInit();
			one[0]=(byte)b;
			++currentPos;
			byte[] buffer=finalizer.switchBuffer();
			int w;
			try {
				w = cipher.update(one, 0, 1, buffer, 0);
			}
			catch (IOException e)
			{
				finalizer.switchBuffer();
				throw e;
			}
			doFinal=true;
			initPossible=true;
			if (w>0) {
				os.write(buffer, 0, w);
			}
			else
				finalizer.switchBuffer();
			checkDoFinal(false);
		}

		@Override
		public void setLength(long newLength) throws IOException {
			if (closed)
				throw new IOException("Stream closed");
			if (newLength<0)
				throw new IllegalArgumentException();
			if (newLength==0) {
				os.setLength(0);
				currentPos=0;
				length=0;
			}
			else {
				long round=newLength/ maxPlainTextSizeForEncoding;
				newLength=round * maxEncryptedPartLength+(newLength % maxPlainTextSizeForEncoding);
				os.setLength(newLength);
				length=newLength;
				seek(Math.min(newLength, currentPos));
			}
		}



		@Override
		public void seek(long _pos) throws IOException {
			if (closed)
				throw new IOException("Stream closed");
			if (!supportRandomEncryptionAndRandomDecryption())
				throw new IOException("Random encryption impossible");
			long round = _pos / maxPlainTextSizeForEncoding;
			if (wrappedIVAndSecretKey!=null) {
				long p = round * maxEncryptedPartLength;
				int mod=(int)(_pos % maxPlainTextSizeForEncoding);
				if (mod%getCounterStepInBytes()!=0)
					throw new IOException("The position is not aligned with the cipher block size");
				int counter=mod/getCounterStepInBytes();

				AbstractWrappedIVs<?, ?> IvsAndSecretKeys;
				if (manualIvsAndSecretKeys!=null)
				{
					IvsAndSecretKeys=manualIvsAndSecretKeys;
					os.seek(p);
					manualIvsAndSecretKeys.setCurrentIV(round, os, useExternalCounter()?externalCounter:null);
				}
				else {
					IvsAndSecretKeys=wrappedIVAndSecretKey;
					if (wrappedIVAndSecretKey.getSerializedElementSizeInBytes()+p>=os.length())
					{
						os.seek(p);
						if (wrappedIVAndSecretKey.getElement(round)==null)
							wrappedIVAndSecretKey.generateNewElement(round, os, useExternalCounter() ? externalCounter : null);
						else
							wrappedIVAndSecretKey.setCurrentIV(round, os, useExternalCounter() ? externalCounter : null);
					}
					else {
						RandomInputStream ris = os.getRandomInputStream();
						ris.seek(p);
						wrappedIVAndSecretKey.pushNewElementAndSetCurrentIV(round, ris, useExternalCounter() ? externalCounter : null);
						os.seek(p+wrappedIVAndSecretKey.getSerializedElementSizeInBytes());
					}
					//ris.readFully(iv);
				}

				initCipherForEncryptionWithIvAndCounter(cipher, IvsAndSecretKeys, counter);

			}
			else
			{
				long add=cipher.getOutputSize((int)(_pos % maxPlainTextSizeForEncoding));
				if (add>0)
					add+=getIVSizeBytesWithoutExternalCounter();
				os.seek(round * maxEncryptedPartLength+add);
				initCipherForEncryption(cipher);
			}
			if (associatedData!=null && lenAD>0)
				cipher.updateAAD(associatedData, offAD, lenAD);
			currentPos=_pos;
		}

		@Override
		public long currentPosition() {
			return currentPos;
		}

		@Override
		public boolean isClosed() {
			return closed;
		}

		@Override
		protected RandomInputStream getRandomInputStreamImpl() throws IOException {
			throw new IOException(new IllegalAccessException());
		}

		@Override
		public void flush() throws IOException {
			os.flush();
		}

		@Override
		public void close() throws IOException {
			if (closed)
				return;
			try {
				checkDoFinal(true);
			}
			finally {
				flush();

				if (closeOutputStreamWhenClosingCipherOutputStream)
					os.close();
				if (replaceMainKeyWhenClosingStream)
				{
					replaceMainKeyByLastDerivedSecretKey(wrappedIVAndSecretKey);
				}
				wrappedIVAndSecretKey=null;
				closed=true;
			}

		}

	}
	protected RandomOutputStream getCipherOutputStreamForEncryption(final RandomOutputStream os, final boolean closeOutputStreamWhenClosingCipherOutputStream, final byte[] associatedData, final int offAD, final int lenAD, final byte[] externalCounter, final AbstractWrappedIVs<?, ?> manualIvsAndSecretKeys, boolean replaceMainKeyWhenClosingStream) throws
			IOException{
		CommonCipherOutputStream res= new CommonCipherOutputStream(os, manualIvsAndSecretKeys, externalCounter, associatedData, offAD, lenAD, closeOutputStreamWhenClosingCipherOutputStream, replaceMainKeyWhenClosingStream);
		if (isUsingSideChannelMitigation())
			return new CPUUsageAsDecoyOutputStream<>(res);
		else
			return res;
	}

	public int getMaxPlainTextSizeForEncoding()
	{
		return maxPlainTextSizeForEncoding;
	}

	void setMaxPlainTextSizeForEncoding(int maxPlainTextSizeForEncoding) throws IOException {
		if (maxPlainTextSizeForEncoding<32)
			throw new IllegalArgumentException();
		assert cipher != null;
		if (cipher.getMode()!= Cipher.ENCRYPT_MODE || mustAlterIVForOutputSizeComputation())
		{
			initCipherForEncryptionWithNullIV(cipher);
		}
		this.maxPlainTextSizeForEncoding=maxPlainTextSizeForEncoding;
		AbstractWrappedIVs<?, ?> wrappedIVAndSecretKey=getWrappedIVAndSecretKeyInstance();
		this.IvAndSecretKeySizeInBytesWithoutExternalCounter=(wrappedIVAndSecretKey==null?getIVSizeBytesWithoutExternalCounter():wrappedIVAndSecretKey.getSerializedElementSizeInBytes());
		this.maxEncryptedPartLength =cipher.getOutputSize(maxPlainTextSizeForEncoding)+ this.IvAndSecretKeySizeInBytesWithoutExternalCounter;

	}

	public final int getIvAndSecretKeySizeInBytesWithoutExternalCounter()
	{
		assert this.maxPlainTextSizeForEncoding>0;
		return IvAndSecretKeySizeInBytesWithoutExternalCounter;
	}


	protected boolean mustAlterIVForOutputSizeComputation()
	{
		return false;
	}
	public long getOutputSizeAfterEncryption(long inputLen) throws IOException {
		if (inputLen<0)
			throw new IllegalArgumentException();
		if (inputLen==0)
			return 0;
		if (previousAskedLengthForEncryption==inputLen)
			return previousOutputSizeAfterEncryption;
		long add=inputLen % maxPlainTextSizeForEncoding;
		if (add>0) {

			assert cipher != null;
			if (cipher.getMode()!= Cipher.ENCRYPT_MODE || mustAlterIVForOutputSizeComputation())
			{
				initCipherForEncryptionWithNullIV(cipher);
			}
			add = cipher.getOutputSize((int)add)+getIvAndSecretKeySizeInBytesWithoutExternalCounter();
		}
		previousAskedLengthForEncryption=inputLen;
		return previousOutputSizeAfterEncryption=((inputLen / maxPlainTextSizeForEncoding) * maxEncryptedPartLength)+add;

	}


	protected abstract boolean includeIV();
	public void initCipherForEncryption(AbstractCipher cipher) throws IOException {
		throw new IllegalAccessError();
	}

	public void initCipherForEncryptionWithNullIV(AbstractCipher cipher)
			throws IOException
	{
		throw new IllegalAccessError();
	}


}

/*
Copyright or © or Copr. Jason Mahdjoub (04/02/2016)

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

import com.distrimind.util.FileTools;
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
public abstract class AbstractEncryptionOutputAlgorithm implements Zeroizable {
	final static int BUFFER_SIZE = FileTools.BUFFER_SIZE;

	protected final AbstractCipher cipher;

	protected byte[] buffer;
	protected int bufferInSize;
	//protected byte[] bufferOut;
	protected int maxPlainTextSizeForEncoding;
	protected int maxEncryptedPartLength;
	private final byte[] one=new byte[1];
	protected final byte[] iv ;
	private long previousAskedLengthForEncryption=-1;
	private long previousOutputSizeAfterEncryption;


	@Override
	public void zeroize() {
		if (buffer!=null) {
			Arrays.fill(buffer, (byte) 0);
			buffer = null;
		}
	}
	@Override
	public boolean isDestroyed() {
		return buffer==null;
	}

	@SuppressWarnings("deprecation")
	@Override
	protected void finalize() {
		zeroize();
	}

	public byte getBlockModeCounterBytes() {
		return (byte)0;
	}
	
	public boolean useExternalCounter()
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
		buffer=null;
		iv=null;
	}

	protected AbstractEncryptionOutputAlgorithm(AbstractCipher cipher, int ivSizeBytes) {
		if (cipher == null)
			throw new NullPointerException("cipher");
		this.cipher = cipher;
		if (includeIV()) {
			iv = new byte[ivSizeBytes];
		}
		else
			iv = null;
	}

	protected void initBufferAllocatorArgs() throws IOException {
		int bol=(int) getOutputSizeAfterEncryption(bufferInSize =BUFFER_SIZE);
		if (bol>BUFFER_SIZE*2)
		{
			bol=(int) getOutputSizeAfterEncryption(bufferInSize =4096);
		}
		zeroize();
		buffer=new byte[bol];
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

	protected abstract void initCipherForEncryptionWithIvAndCounter(AbstractCipher cipher, byte[] iv, int counter) throws IOException;
	protected abstract void initCipherForEncryptionWithIv(AbstractCipher cipher, byte[] iv) throws IOException;

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

	protected abstract AbstractCipher getCipherInstance() throws IOException;
	protected static void checkLimits(byte[] b, int off, int len)
	{
		if (b==null)
			throw new NullPointerException();
		if ((off | len) < 0 || len > b.length - off)
			throw new IndexOutOfBoundsException();
	}
	protected abstract int getCounterStepInBytes();

	public abstract boolean supportRandomEncryptionAndRandomDecryption();

	public CommonCipherOutputStream getCipherOutputStreamForEncryption(final RandomOutputStream os, boolean closeOutputStreamWhenClosingCipherOutputStream) throws IOException
	{
		return getCipherOutputStreamForEncryption(os, closeOutputStreamWhenClosingCipherOutputStream, null, 0,0, null);
	}
	public CommonCipherOutputStream getCipherOutputStreamForEncryption(final RandomOutputStream os, boolean closeOutputStreamWhenClosingCipherOutputStream, final byte[] associatedData, final int offAD, final int lenAD) throws IOException
	{
		return getCipherOutputStreamForEncryption(os, closeOutputStreamWhenClosingCipherOutputStream, associatedData, offAD, lenAD, null);
	}
	public CommonCipherOutputStream getCipherOutputStreamForEncryption(final RandomOutputStream os, boolean closeOutputStreamWhenClosingCipherOutputStream, byte[] externalCounter) throws IOException
	{
		return getCipherOutputStreamForEncryption(os, closeOutputStreamWhenClosingCipherOutputStream, null, 0,0, externalCounter);
	}

	public CommonCipherOutputStream getCipherOutputStreamForEncryption(final RandomOutputStream os, boolean closeOutputStreamWhenClosingCipherOutputStream, final byte[] associatedData, final int offAD, final int lenAD, final byte[] externalCounter) throws
			IOException{
		return getCipherOutputStreamForEncryption(os, closeOutputStreamWhenClosingCipherOutputStream, associatedData, offAD, lenAD, externalCounter, null);
	}
	class CommonCipherOutputStream extends RandomOutputStream
	{
		long length;
		long currentPos;
		boolean closed;
		private boolean doFinal;
		boolean supportRandomAccess;

		RandomOutputStream os;
		private byte[][] manualIvs;
		private byte[] externalCounter;
		private byte[] associatedData;
		private int offAD, lenAD;
		private boolean closeOutputStreamWhenClosingCipherOutputStream;


		CommonCipherOutputStream(RandomOutputStream os, byte[][] manualIvs, byte[] externalCounter, byte[] associatedData, int offAD, int lenAD, boolean closeOutputStreamWhenClosingCipherOutputStream) throws IOException {
			set(os, manualIvs, externalCounter, associatedData, offAD, lenAD, closeOutputStreamWhenClosingCipherOutputStream);
		}

		void set(RandomOutputStream os, byte[][] manualIvs, byte[] externalCounter, byte[] associatedData, int offAD, int lenAD, boolean closeOutputStreamWhenClosingCipherOutputStream) throws IOException {
			length=0;
			currentPos=0;
			closed=false;
			doFinal=false;
			supportRandomAccess=supportRandomEncryptionAndRandomDecryption();

			this.os = os;
			this.manualIvs = manualIvs;
			this.externalCounter = externalCounter;
			this.associatedData = associatedData;
			this.offAD = offAD;
			this.lenAD = lenAD;
			this.closeOutputStreamWhenClosingCipherOutputStream = closeOutputStreamWhenClosingCipherOutputStream;
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
					int s = cipher.doFinal(buffer, 0);
					if (s > 0)
						os.write(buffer, 0, s);
				}
				doFinal = false;
			}
		}

		private long checkInit() throws IOException {
			long mod=currentPos % maxPlainTextSizeForEncoding;
			if (mod == 0) {
				long round=currentPos/ maxPlainTextSizeForEncoding;
				checkDoFinal(false);
				if (includeIV()) {
					byte[] iv;
					if (manualIvs!=null)
					{
						if (externalCounter==null)
							initCipherForEncryptionWithIv(cipher, manualIvs[(int)round]);
						else {
							System.arraycopy(manualIvs[(int) round], 0, iv = AbstractEncryptionOutputAlgorithm.this.iv, 0, getIVSizeBytesWithoutExternalCounter());
							if (useExternalCounter())
								System.arraycopy(externalCounter, 0, iv, getIVSizeBytesWithoutExternalCounter(), externalCounter.length);
							initCipherForEncryption(cipher, iv);
						}
					}
					else {
						iv = initCipherForEncryption(cipher, externalCounter);
						int ivl=getIVSizeBytesWithoutExternalCounter();
						os.write(iv, 0, ivl);
					}

				}
				else {
					initCipherForEncryptionWithNullIV(cipher);
				}

				if (associatedData != null && lenAD > 0)
					cipher.updateAAD(associatedData, offAD, lenAD);
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
				if (len> bufferInSize) {
					int outLen = cipher.getOutputSize(s);
					if (buffer.length < outLen) {
						zeroize();
						buffer = new byte[outLen];
					}
				}
				int w=cipher.update(b, off, s, buffer, 0);
				doFinal=true;
				currentPos+=s;
				if (w>0) {
					os.write(buffer, 0, w);
				}

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
			int w=cipher.update(one, 0, 1, buffer, 0);
			doFinal=true;
			if (w>0) {
				os.write(buffer, 0, w);
			}
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
				/*if (_pos<0 || _pos>length)
					throw new IllegalArgumentException();*/
			if (!supportRandomEncryptionAndRandomDecryption())
				throw new IOException("Random encryption impossible");
			long round = _pos / maxPlainTextSizeForEncoding;
			if (includeIV()) {
				long p = round * maxEncryptedPartLength;
				int mod=(int)(_pos % maxPlainTextSizeForEncoding);
				if (mod%getCounterStepInBytes()!=0)
					throw new IOException("The position is not aligned with the cipher block size");
				int counter=mod/getCounterStepInBytes();

				if (manualIvs!=null)
				{
					if (useExternalCounter())
						System.arraycopy(manualIvs[(int)round], 0, iv, 0, getIVSizeBytesWithoutExternalCounter());
					else
						System.arraycopy(manualIvs[(int)round], 0, iv, 0, getIVSizeBytesWithExternalCounter());
				}
				else {
					RandomInputStream ris = os.getRandomInputStream();
					os.getRandomInputStream().seek(p);
					ris.readFully(iv);
				}
				if (useExternalCounter()) {
					System.arraycopy(externalCounter, 0, iv, getIVSizeBytesWithoutExternalCounter(), externalCounter.length);
				}
				initCipherForEncryptionWithIvAndCounter(cipher, iv, counter);
				if (mod>0 || manualIvs!=null) {
					mod+=getIVSizeBytesWithoutExternalCounter();
				}
				p += mod;
				os.seek(p);

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
			checkDoFinal(true);
			flush();
			if (closeOutputStreamWhenClosingCipherOutputStream)
				os.close();
			closed=true;
		}

	}
	protected CommonCipherOutputStream getCipherOutputStreamForEncryption(final RandomOutputStream os, final boolean closeOutputStreamWhenClosingCipherOutputStream, final byte[] associatedData, final int offAD, final int lenAD, final byte[] externalCounter, final byte[][] manualIvs) throws
			IOException{
		return new CommonCipherOutputStream(os, manualIvs, externalCounter, associatedData, offAD, lenAD, closeOutputStreamWhenClosingCipherOutputStream);
	}

	public int getMaxPlainTextSizeForEncoding()
	{
		return maxPlainTextSizeForEncoding;
	}

	void setMaxPlainTextSizeForEncoding(int maxPlainTextSizeForEncoding) throws IOException {
		initCipherForEncryptionWithNullIV(cipher);
		this.maxPlainTextSizeForEncoding=maxPlainTextSizeForEncoding;
		this.maxEncryptedPartLength =cipher.getOutputSize(maxPlainTextSizeForEncoding)+getIVSizeBytesWithoutExternalCounter();

	}

	
	public abstract int getIVSizeBytesWithExternalCounter();
	public final int getIVSizeBytesWithoutExternalCounter()
	{
		return getIVSizeBytesWithExternalCounter()-(useExternalCounter()?getBlockModeCounterBytes():0);
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

			if (cipher.getMode()!= Cipher.ENCRYPT_MODE || mustAlterIVForOutputSizeComputation())
			{
				initCipherForEncryptionWithNullIV(cipher);
			}
			add = cipher.getOutputSize((int)add)+getIVSizeBytesWithoutExternalCounter();
		}
		previousAskedLengthForEncryption=inputLen;
		return previousOutputSizeAfterEncryption=((inputLen / maxPlainTextSizeForEncoding) * maxEncryptedPartLength)+add;

	}


	protected abstract boolean includeIV();
	public void initCipherForEncryption(AbstractCipher cipher) throws IOException {
		initCipherForEncryption(cipher, null);
	}
	public abstract byte[] initCipherForEncryption(AbstractCipher cipher, byte[] externalCounter)
			throws IOException;

	public abstract void initCipherForEncryptionWithNullIV(AbstractCipher cipher)
			throws IOException;

	public abstract boolean isPostQuantumEncryption();

}

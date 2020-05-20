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

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;
import java.io.IOException;

/**
 * 
 * @author Jason Mahdjoub
 * @version 5.0
 * @since Utils 1.5
 */
public abstract class AbstractEncryptionOutputAlgorithm {
	final static int BUFFER_SIZE = FileTools.BUFFER_SIZE;

	protected final AbstractCipher cipher;

	protected final byte[] buffer;
	protected byte[] bufferOut;
	protected int maxPlainTextSizeForEncoding;
	protected int maxEncryptedPartLength;
	private final byte[] one=new byte[1];
	protected final byte[] iv ;
	
	public byte getBlockModeCounterBytes() {
		return (byte)0;
	}
	
	public boolean useExternalCounter()
	{
		return false;
	}

	protected AbstractEncryptionOutputAlgorithm()
	{
		super();
		cipher=null;
		buffer=null;
		bufferOut=null;
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

		buffer=new byte[BUFFER_SIZE];

	}

	protected void initBufferAllocatorArgs() throws IOException {
		bufferOut=new byte[(int)getOutputSizeForEncryption(BUFFER_SIZE)];
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
		try (RandomByteArrayOutputStream baos = new RandomByteArrayOutputStream((int)getOutputSizeForEncryption(len))) {
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

	public void encode(byte[] bytes, int off, int len, byte[] associatedData, int offAD, int lenAD, RandomOutputStream os, byte[] externalCounter) throws IOException{
		RandomInputStream ris=new RandomByteArrayInputStream(bytes);
		try {
			if (len != bytes.length)
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

		try(RandomOutputStream cos = getCipherOutputStream(os, associatedData, offAD, lenAD, externalCounter))
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
	public RandomOutputStream getCipherOutputStream(final RandomOutputStream os) throws IOException
	{
		return getCipherOutputStream(os, null, 0,0, null);
	}
	public RandomOutputStream getCipherOutputStream(final RandomOutputStream os, final byte[] associatedData, final int offAD, final int lenAD) throws IOException
	{
		return getCipherOutputStream(os, associatedData, offAD, lenAD, null);
	}
	public RandomOutputStream getCipherOutputStream(final RandomOutputStream os, byte[] externalCounter) throws IOException
	{
		return getCipherOutputStream(os, null, 0,0, externalCounter);
	}

	protected abstract int getCounterStepInBytes();

	public abstract boolean supportRandomEncryptionAndRandomDecryption();
	public RandomOutputStream getCipherOutputStream(final RandomOutputStream os, final byte[] associatedData, final int offAD, final int lenAD, final byte[] externalCounter) throws
			IOException{
		return getCipherOutputStream(os, associatedData, offAD, lenAD, externalCounter, null);
	}
	protected RandomOutputStream getCipherOutputStream(final RandomOutputStream os, final byte[] associatedData, final int offAD, final int lenAD, final byte[] externalCounter, final byte[][] manualIvs) throws
			IOException{
		os.seek(0);
		final boolean supportRandomAccess=supportRandomEncryptionAndRandomDecryption();


		return new RandomOutputStream() {
			long length=0;
			long currentPos=0;
			boolean closed=false;
			private boolean doFinal=true;
			private byte[] buffer=AbstractEncryptionOutputAlgorithm.this.buffer;

			private void checkDoFinal(boolean force) throws IOException {
				if (doFinal && (currentPos%maxPlainTextSizeForEncoding==0 || force))
				{
					try {
						int s=cipher.doFinal(buffer, 0);
						os.write(buffer, 0, s);
						doFinal=false;
					} catch (IllegalBlockSizeException | BadPaddingException | ShortBufferException e) {
						throw new IOException(e);
					}
				}
			}

			private long checkInit() throws IOException {
				if (currentPos % maxPlainTextSizeForEncoding == 0) {
					long round=currentPos/ maxPlainTextSizeForEncoding;
					if (round>0){
						checkDoFinal(false);
					}
					if (includeIV()) {
						byte[] iv;
						if (manualIvs!=null)
						{
							if (externalCounter==null)
								initCipherForEncryptionWithIvAndCounter(cipher, iv=manualIvs[(int)round], 0);
							else {
								System.arraycopy(manualIvs[(int) round], 0, iv = AbstractEncryptionOutputAlgorithm.this.iv, 0, getIVSizeBytesWithoutExternalCounter());
								if (useExternalCounter())
									System.arraycopy(externalCounter, 0, iv, getIVSizeBytesWithoutExternalCounter(), externalCounter.length);
								initCipherForEncryptionWithIvAndCounter(cipher, iv, 0);
							}
						}
						else {
							iv = initCipherForEncrypt(cipher, externalCounter);
						}
						os.write(iv, 0, getIVSizeBytesWithoutExternalCounter());
					}
					else {
						initCipherForEncryptWithNullIV(cipher);
					}

					if (associatedData != null && lenAD > 0)
						cipher.updateAAD(associatedData, offAD, lenAD);
					return maxPlainTextSizeForEncoding;
				}
				return (int) (currentPos % maxPlainTextSizeForEncoding);
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
					int outLen=cipher.getOutputSize(s);
					if (buffer.length<outLen)
					{
						buffer=new byte[outLen];
					}
					try {
						int w=cipher.update(b, off, s, buffer, 0);
						doFinal=true;
						currentPos+=s;
						if (w>0) {
							os.write(buffer, 0, w);
						}
					} catch (ShortBufferException e) {
						throw new IOException(e);
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
				try {
					int w=cipher.update(one, 0, 1, buffer, 0);
					doFinal=true;
					if (w>0) {
						os.write(buffer, 0, w);
					}
				} catch (ShortBufferException e) {
					throw new IOException(e);
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
				if (_pos<0 || _pos>length)
					throw new IllegalArgumentException();
				if (!supportRandomAccess)
					throw new IOException("Random encryption impossible");
				long round = _pos / maxPlainTextSizeForEncoding;
				if (includeIV()) {
					long p = round * maxEncryptedPartLength;
					int mod=(int)(_pos % maxPlainTextSizeForEncoding);
					int counter=mod/getCounterStepInBytes();
					byte[] iv;
					if (manualIvs!=null)
					{
						if (useExternalCounter())
							System.arraycopy(manualIvs[(int)round], 0, iv=AbstractEncryptionOutputAlgorithm.this.iv, 0, getIVSizeBytesWithoutExternalCounter());
						else
							iv=manualIvs[(int)round];
					}
					else {
						RandomInputStream ris = os.getRandomInputStream();
						os.getRandomInputStream().seek(p);
						ris.readFully(iv=AbstractEncryptionOutputAlgorithm.this.iv);
					}
					if (useExternalCounter())
						System.arraycopy(externalCounter, 0, iv, getIVSizeBytesWithoutExternalCounter(), externalCounter.length);

					if (mod>0) {
						mod = cipher.getOutputSize(mod)+getIVSizeBytesWithoutExternalCounter();
					}
					p += mod;
					os.seek(p);
					initCipherForEncryptionWithIvAndCounter(cipher, iv, counter);
				}
				else
				{
					long add=cipher.getOutputSize((int)(_pos % maxPlainTextSizeForEncoding));
					if (add>0)
						add+=getIVSizeBytesWithoutExternalCounter();
					os.seek(round * maxEncryptedPartLength+add);
					initCipherForEncrypt(cipher);
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
				closed=true;
			}


		};

	}

	public int getMaxPlainTextSizeForEncoding()
	{
		return maxPlainTextSizeForEncoding;
	}

	void setMaxPlainTextSizeForEncoding(int maxPlainTextSizeForEncoding) throws IOException {
		initCipherForEncryptWithNullIV(cipher);
		this.maxPlainTextSizeForEncoding=maxPlainTextSizeForEncoding;
		int maxCipherTextLength = cipher.getOutputSize(maxPlainTextSizeForEncoding);
		this.maxEncryptedPartLength =maxCipherTextLength+getIVSizeBytesWithoutExternalCounter();

	}

	
	public abstract int getIVSizeBytesWithExternalCounter();
	public final int getIVSizeBytesWithoutExternalCounter()
	{
		return getIVSizeBytesWithExternalCounter()-(useExternalCounter()?getBlockModeCounterBytes():0);
	}

	public long getOutputSizeForEncryption(long inputLen) throws IOException {
		if (inputLen<0)
			throw new IllegalArgumentException();
		if (inputLen==0)
			return 0;
		initCipherForEncryptWithNullIV(cipher);
		int add=cipher.getOutputSize((int)(inputLen % maxPlainTextSizeForEncoding));
		if (add>0)
			add+=getIVSizeBytesWithoutExternalCounter();
		return inputLen / maxPlainTextSizeForEncoding * maxEncryptedPartLength+add;

	}


	protected abstract boolean includeIV();
	public void initCipherForEncrypt(AbstractCipher cipher) throws IOException {
		initCipherForEncrypt(cipher, null);
	}
	public abstract byte[] initCipherForEncrypt(AbstractCipher cipher, byte[] externalCounter)
			throws IOException;

	public abstract void initCipherForEncryptWithNullIV(AbstractCipher cipher)
			throws IOException;

	public abstract boolean isPostQuantumEncryption();

}

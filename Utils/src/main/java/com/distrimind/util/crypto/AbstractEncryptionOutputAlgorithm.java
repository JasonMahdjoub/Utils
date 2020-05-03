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

import com.distrimind.util.Bits;
import com.distrimind.util.FileTools;
import com.distrimind.util.io.*;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;

/**
 * 
 * @author Jason Mahdjoub
 * @version 5.0
 * @since Utils 1.5
 */
public abstract class AbstractEncryptionOutputAlgorithm {
	final static int BUFFER_SIZE = FileTools.BUFFER_SIZE;

	protected final AbstractCipher cipher;

	final byte[] nullIV;

	protected final byte[] buffer;
	protected byte[] bufferOut;
	
	
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
		nullIV=null;
		buffer=null;
		bufferOut=null;
	}

	protected AbstractEncryptionOutputAlgorithm(AbstractCipher cipher, int ivSizeBytes) {
		if (cipher == null)
			throw new NullPointerException("cipher");
		this.cipher = cipher;
		if (includeIV())
			nullIV = new byte[ivSizeBytes];
		else
			nullIV = null;
		buffer=new byte[BUFFER_SIZE];
	}

	protected void initBufferAllocatorArgs()
	{
		try
		{
			bufferOut=new byte[getOutputSizeForEncryption(BUFFER_SIZE)];
		} catch (SecurityException | InvalidKeyException | InvalidAlgorithmParameterException | NoSuchAlgorithmException | InvalidKeySpecException | NoSuchProviderException e) {
			throw new IllegalAccessError(e.getMessage());
		}
	}
	
	
	/*protected void initIV()
	{
		
	}*/
	
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
		try (RandomByteArrayOutputStream baos = new RandomByteArrayOutputStream(getOutputSizeForEncryption(len))) {
			encode(bytes, off, len, associatedData, offAD, lenAD, baos, externalCounter);
			return baos.getBytes();
		} catch (NoSuchAlgorithmException | InvalidKeyException | InvalidKeySpecException | InvalidAlgorithmParameterException | NoSuchProviderException e) {
			throw new IOException(e);
		}
	}
	public void encode(byte[] bytes, int off, int len, RandomOutputStream os) throws IOException{
		encode(bytes, off, len, null,0, 0, os);
	}
	public void encode(byte[] bytes, int off, int len, byte[] associatedData, int offAD, int lenAD, RandomOutputStream os) throws IOException
	{
		encode(bytes, off, len, associatedData, offAD, lenAD, os, null);
	}

	protected abstract void initCipherForEncryptionWithIv(AbstractCipher cipher, byte[] iv);

	public void encode(byte[] bytes, int off, int len, byte[] associatedData, int offAD, int lenAD, RandomOutputStream os, byte[] externalCounter) throws IOException{
		RandomInputStream ris=new RandomByteArrayInputStream(bytes);
		if (len!=bytes.length)
			ris=new LimitedRandomInputStream(ris, off, len);
		encode(ris, associatedData, offAD, lenAD, os, externalCounter);
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

	protected abstract AbstractCipher getCipherInstance() throws NoSuchAlgorithmException,
			NoSuchPaddingException, NoSuchProviderException;
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

	public RandomOutputStream getCipherOutputStream(final RandomOutputStream os, final byte[] associatedData, final int offAD, final int lenAD, final byte[] externalCounter) throws
			IOException{
		byte[] tab;
		try {
			 tab = initCipherForEncrypt(cipher, externalCounter);
		} catch (InvalidKeyException | InvalidAlgorithmParameterException | NoSuchAlgorithmException | InvalidKeySpecException | NoSuchProviderException e) {
			throw new IOException(e);
		}
		final byte[] initialIV=tab;
		final int counterPos = initialIV==null?0:initialIV.length - 4;
		final int initialCounter=initialIV==null?0:Bits.getInt(initialIV, counterPos);
		final long initialOutPos=os.currentPosition();
		return new RandomOutputStream() {

			byte[] iv=null;
			int counter=0;
			final int maxBlockSize=getMaxBlockSizeForEncoding();
			long length=0;
			long currentPos=0;
			//
			int round=0;
			boolean closed=false;
			private final byte[] one=new byte[1];
			private final ArrayList<Long> outPos=new ArrayList<>();


			private int checkInit() throws IOException {
				if (currentPos % maxBlockSize == 0) {
					if (iv == null) {
						round=0;
						if (includeIV()) {
							iv=initialIV;
							counter=initialCounter;
							Bits.putInt(iv, counterPos, counter);
							os.write(iv, 0, getIVSizeBytesWithoutExternalCounter());
							initCipherForEncryptionWithIv(cipher, initialIV);
						}
						else {
							try {
								initCipherForEncryptAndNotChangeIV(cipher);
							} catch (InvalidKeyException | InvalidAlgorithmParameterException | NoSuchAlgorithmException | InvalidKeySpecException | NoSuchProviderException e) {
								throw new IOException(e);
							}
						}
					} else {

						try {
							byte[] f=cipher.doFinal();
							if (f!=null && f.length>0)
								os.write(f);
							if (outPos.size()>round) {
								outPos.set(round, os.currentPosition());
							}
							else
								outPos.add(os.currentPosition());
						} catch (IllegalBlockSizeException | BadPaddingException e) {
							throw new IOException(e);
						}
						++round;
						if (includeIV()) {

							counter = initialCounter + round;
							Bits.putInt(iv, counterPos, counter);
							initCipherForEncryptionWithIv(cipher, iv);
						}
						else {
							try {
								initCipherForEncryptAndNotChangeIV(cipher);
							} catch (InvalidKeyException | InvalidAlgorithmParameterException | NoSuchAlgorithmException | InvalidKeySpecException | NoSuchProviderException e) {
								throw new IOException(e);
							}
						}
					}
					if (associatedData != null && lenAD > 0)
						cipher.updateAAD(associatedData, offAD, lenAD);
					return maxBlockSize;
				}
				return (int) (currentPos % maxBlockSize);
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
				int l=checkInit();
				while (len>0) {
					int s=Math.min(len, l);
					os.write(cipher.update(b, off, s));
					len-=s;
					currentPos+=s;
					if (len>0) {
						off+=s;
						checkInit();
					}
				}
				length=Math.max(length, currentPos);
			}
			@Override
			public void write(int b) throws IOException {
				if (closed)
					throw new IOException("Stream closed");
				checkInit();
				one[0]=(byte)b;
				os.write(cipher.update(one));
			}

			@Override
			public void setLength(long newLength) throws IOException {
				if (closed)
					throw new IOException("Stream closed");
				if (newLength<0)
					throw new IllegalArgumentException();
				if (newLength==0) {
					os.setLength(initialOutPos);
					currentPos=0;
					length=0;
					iv=null;
				}
				else {
					int ivL=0;
					if (includeIV()) {
						ivL = getIVSizeBytesWithoutExternalCounter();
					}
					os.setLength(ivL+newLength);
					currentPos=Math.min(newLength, currentPos);
					length=newLength;
				}
			}

			@Override
			public void seek(long _pos) throws IOException {
				if (closed)
					throw new IOException("Stream closed");
				round = (int) (_pos / maxBlockSize);
				long p;
				if (round>0)
					p=outPos.get(round);
				else
					p=initialOutPos;
				os.seek(p+_pos%maxBlockSize);
				if (includeIV()) {

					counter = initialCounter+((int) (_pos % maxBlockSize)) + round;
					Bits.putInt(iv, counterPos, counter);
					initCipherForEncryptionWithIv(cipher, iv);
				}
				else {
					try {
						initCipherForEncryptAndNotChangeIV(cipher);
					} catch (InvalidKeyException | InvalidAlgorithmParameterException | NoSuchAlgorithmException | InvalidKeySpecException | NoSuchProviderException e) {
						throw new IOException(e);
					}
				}

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
				if (length>0) {

					try {
						byte[] f=cipher.doFinal();
						if (f!=null && f.length>0)
							os.write(f);
					} catch (IllegalBlockSizeException | BadPaddingException e) {
						throw new IOException(e);
					}
				}
				flush();
				closed=true;
			}


		};

	}

	public abstract int getMaxBlockSizeForEncoding();

	
	public abstract int getIVSizeBytesWithExternalCounter();
	public final int getIVSizeBytesWithoutExternalCounter()
	{
		return getIVSizeBytesWithExternalCounter()-(useExternalCounter()?getBlockModeCounterBytes():0);
	}
	
	public int getOutputSizeForEncryption(int inputLen)
			throws InvalidKeyException, InvalidAlgorithmParameterException,
			NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
		initCipherForEncryptAndNotChangeIV(cipher);
		int maxBlockSize = getMaxBlockSizeForEncoding();
		if (this instanceof SymmetricEncryptionAlgorithm) {
			if (includeIV()) {
				return cipher.getOutputSize(inputLen) + getIVSizeBytesWithoutExternalCounter();
			} else {
				return cipher.getOutputSize(inputLen);
			}
		}
		int div = inputLen / maxBlockSize;
		int mod = inputLen % maxBlockSize;
		int res = 0;
		if (div > 0)
			res += cipher.getOutputSize(maxBlockSize) * div;
		
		if (mod > 0)
			res += cipher.getOutputSize(mod);
		if (includeIV())
			res += cipher.getBlockSize();
		return res;
	}

	protected abstract boolean includeIV();
	public void initCipherForEncrypt(AbstractCipher cipher) throws InvalidKeyException,
	InvalidAlgorithmParameterException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
		initCipherForEncrypt(cipher, null);
	}
	public abstract byte[] initCipherForEncrypt(AbstractCipher cipher, byte[] externalCounter)
			throws InvalidKeyException, InvalidAlgorithmParameterException,
			NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException;

	public abstract void initCipherForEncryptAndNotChangeIV(AbstractCipher cipher)
			throws InvalidKeyException, InvalidAlgorithmParameterException,
			NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException;

	public abstract boolean isPostQuantumEncryption();

}

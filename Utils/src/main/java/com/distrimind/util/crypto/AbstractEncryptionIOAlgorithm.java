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
import com.distrimind.util.io.LimitedRandomInputStream;
import com.distrimind.util.io.RandomByteArrayInputStream;
import com.distrimind.util.io.RandomInputStream;

import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import java.io.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;

/**
 * 
 * @author Jason Mahdjoub
 * @version 4.0
 * @since Utils 1.5
 */
public abstract class AbstractEncryptionIOAlgorithm extends AbstractEncryptionOutputAlgorithm implements IEncryptionInputAlgorithm{

	protected AbstractEncryptionIOAlgorithm()
	{
		super();
	}

	protected AbstractEncryptionIOAlgorithm(AbstractCipher cipher, int ivSizeBytes) {
		super(cipher, ivSizeBytes);

	}
	@Override
	public byte[] decode(byte[] bytes)
			throws IOException {
		return decode(bytes, 0, bytes.length);
	}
	@Override
	public byte[] decode(byte[] bytes, byte[] associatedData, byte[] externalCounter) throws IOException
	{
		return decode(bytes, 0, bytes.length, associatedData, 0, associatedData==null?0:associatedData.length, externalCounter);
	}
	@Override
	public byte[] decode(byte[] bytes, byte[] associatedData) throws IOException
	{
		return decode(bytes, associatedData, null);
	}
	@Override
	public byte[] decode(byte[] bytes, int off, int len) throws IOException
	{
		return decode(bytes, 0, bytes.length, null, 0, 0);
	}
	@Override
	public byte[] decode(byte[] bytes, int off, int len, byte[] associatedData, int offAD, int lenAD) throws IOException
	{
		return decode(bytes, off, len, associatedData, offAD, lenAD, null);
	}
	@Override
	public byte[] decode(byte[] bytes, int off, int len, byte[] associatedData, int offAD, int lenAD, byte[] externalCounter)
			throws IOException {
		if (len < 0 || off < 0)
			throw new IllegalArgumentException("bytes.length=" + bytes.length + ", off=" + off + ", len=" + len);
		if (off > bytes.length)
			throw new IllegalArgumentException("bytes.length=" + bytes.length + ", off=" + off + ", len=" + len);
		if (off + len > bytes.length)
			throw new IllegalArgumentException("bytes.length=" + bytes.length + ", off=" + off + ", len=" + len);
		RandomInputStream bais = new RandomByteArrayInputStream(bytes);
		try  {

			if (len!=bytes.length)
				bais=new LimitedRandomInputStream(bais, off, len);
			return decode(bais, associatedData, offAD, lenAD, externalCounter);
		}
		finally {
			bais.close();
		}
	}
	@Override
	public byte[] decode(RandomInputStream is, byte[] associatedData) throws IOException
	{
		return decode(is, associatedData, 0, associatedData==null?0:associatedData.length);
	}
	@Override
	public byte[] decode(RandomInputStream is) throws IOException
	{
		return decode(is, null, 0, 0);
	}
	@Override
	public byte[] decode(RandomInputStream is, byte[] associatedData, int offAD, int lenAD) throws IOException
	{
		return decode(is, associatedData, offAD, lenAD, (byte[])null);
	}
	@Override
	public byte[] decode(RandomInputStream is, byte[] associatedData, int offAD, int lenAD, byte[] externalCounter)
			throws IOException {
		try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
			this.decode(is, associatedData, offAD, lenAD, baos, externalCounter);
			return baos.toByteArray();
		}
	}
	@Override
	public void decode(RandomInputStream is, byte[] associatedData, OutputStream os) throws IOException
	{
		decode(is, associatedData, 0, associatedData==null?0:associatedData.length, os);
	}
	@Override
	public void decode(RandomInputStream is, OutputStream os, byte[] externalCounter) throws IOException
	{
		decode(is, os, -1, externalCounter);
	}
	@Override
	public void decode(RandomInputStream is, OutputStream os) throws IOException
	{
		decode(is, null, 0, 0, os);
	}
	@Override
	public void decode(RandomInputStream is, byte[] associatedData, int offAD, int lenAD, OutputStream os) throws IOException
	{
		decode(is, associatedData, offAD, lenAD, os, null);
	}
	@Override
	public void decode(RandomInputStream is, byte[] associatedData, int offAD, int lenAD, OutputStream os, byte[] externalCounter) throws IOException
	{
		decode(is, associatedData, offAD, lenAD, os, -1, externalCounter);
	}
	@Override
	public void decode(RandomInputStream is, OutputStream os, int length) throws IOException
	{
		decode(is, null, 0, 0, os, length);
	}
	@Override
	public void decode(RandomInputStream is, OutputStream os, int length, byte[] externalCounter) throws IOException
	{
		decode(is, null, 0, 0, os, length, externalCounter);
	}
	@Override
	public void decode(RandomInputStream is, byte[] associatedData, OutputStream os, int length) throws IOException
	{
		decode(is, associatedData, 0, associatedData==null?0:associatedData.length, os, length);
	}

	private byte[] iv = null;
	@Override
	public void decode(RandomInputStream is, byte[] associatedData, int offAD, int lenAD, OutputStream os, int length)
			throws IOException{
		decode(is, associatedData, offAD, lenAD, os, length, null);
	}
	
	protected byte[] readIV(InputStream is, byte[] externalCounter) throws IOException
	{
		if (includeIV()) {
			if (this.iv==null)
				this.iv = new byte[getIVSizeBytesWithExternalCounter()];
			
			if (useExternalCounter() && (externalCounter==null || externalCounter.length!=getBlockModeCounterBytes()))
				throw new IllegalArgumentException("External counter must have the next pre-defined size ; "+getBlockModeCounterBytes());
			int sizeWithoutExC=getIVSizeBytesWithoutExternalCounter();
			int read = is.read(this.iv, 0, sizeWithoutExC);
			if (read != sizeWithoutExC)
				throw new IOException("read=" + read + ", iv.length=" + iv.length);
			if (useExternalCounter())
			{
				int j=0;
				for (int i=sizeWithoutExC;i<this.iv.length;i++)
				{
					this.iv[i]=externalCounter[j++];
				}
			}
			return this.iv;
		}
		return null;
	}


	@Override
	public void decode(RandomInputStream is, byte[] associatedData, int offAD, int lenAD, OutputStream os, int length,  byte[] externalCounter)
			throws IOException{
		try(RandomInputStream in = getCipherInputStream(is, associatedData, offAD, lenAD, externalCounter))
		{
			in.transferTo(os, length);
		}
		os.flush();
	}

	@Override
	public RandomInputStream getCipherInputStream(final RandomInputStream is) throws IOException
	{
		return getCipherInputStream(is, null, 0, 0, null);
	}
	@Override
	public RandomInputStream getCipherInputStream(final RandomInputStream is, byte[] externalCounter) throws IOException
	{
		return getCipherInputStream(is, null, 0, 0, externalCounter);
	}
	@Override
	public RandomInputStream getCipherInputStream(final RandomInputStream is, final byte[] associatedData, final int offAD, final int lenAD) throws IOException
	{
		return getCipherInputStream(is, associatedData, offAD, lenAD, null);
	}


	@Override
	public RandomInputStream getCipherInputStream(final RandomInputStream is, final byte[] associatedData, final int offAD, final int lenAD, byte[] externalCounter)
			throws IOException {
		try {
			final AbstractCipher cipher = getCipherInstance();
			final byte[] initialIV=readIV(is, externalCounter);

			final int counterPos = initialIV==null?0:initialIV.length - 4;
			final int initialCounter=initialIV==null?0:Bits.getInt(initialIV, counterPos);
			final long initialIsPos=is.currentPosition();
			final long length=is.length()-initialIsPos;

			return new RandomInputStream() {
				private long pos=0;
				int round=0;
				int counter=0;
				private final byte[] buffer=new byte[BUFFER_SIZE];
				final int maxBlockSize=getMaxBlockSizeForEncoding();
				boolean closed=false;

				@Override
				public long length() {
					return length;
				}

				private int checkInit() throws IOException {
					if (pos%maxBlockSize==0)
					{
						round=(int)(pos/maxBlockSize);
						counter=round+initialCounter;
						Bits.putInt(iv, counterPos, counter);
						try {
							initCipherForDecrypt(cipher, iv);
							if (associatedData!=null && lenAD>0)
								cipher.updateAAD(associatedData, offAD, lenAD);
						} catch (InvalidKeyException | InvalidAlgorithmParameterException | NoSuchAlgorithmException | InvalidKeySpecException | NoSuchProviderException e) {
							throw new IOException(e);
						}
						return maxBlockSize;
					}
					return (int) (pos % maxBlockSize);
				}

				@Override
				public int read(byte[] b, int off, int len) throws IOException {
					return read(b, off, len, false);
				}

				private int read(final byte[] b, final int off, final int len, final boolean fully) throws IOException {
					if (closed)
						throw new IOException("Stream closed");
					checkLimits(b, off, len);
					int total=0;
					do {
						int s=Math.min(checkInit(), len);

						do {
							int s3=Math.min(s, buffer.length);
							try {
								int s2=is.read(buffer, 0, s3);
								if (s2==-1)
								{
									if (fully)
									{
										if (total!=len)
											throw new EOFException();
									}
									if (total==0)
									{
										return -1;
									}
									else
										return total;
								}
								int w=cipher.update(buffer, 0, s2, b, off);
								s-=s2;
								total+=w;
								pos+=w;
								if (!fully && s3!=s2)
									return total;
							} catch (ShortBufferException e) {
								throw new IOException(e);
							}

						} while(s>0);
					} while (len>total);
					return total;
				}

				@Override
				public int read() throws IOException {
					if (closed)
						throw new IOException("Stream closed");
					checkInit();

					int v=is.read(buffer, 0, 1);
					++pos;
					if (v<0)
						return v;
					else
					{
						try
						{
							cipher.update(buffer, 0, 1, buffer, 1);
							return buffer[1] & 0xFF;
						} catch (ShortBufferException e) {
							throw new IOException(e);
						}

					}
				}

				@Override
				public void seek(long _pos) throws IOException {
					if (closed)
						throw new IOException("Stream closed");
					if (_pos<0)
						throw new IllegalArgumentException();
					if (_pos>length)
						throw new IllegalArgumentException();
					this.pos=_pos;
					round=(int)(pos/maxBlockSize);
					counter=(int)(pos%maxBlockSize+initialCounter+round);
					Bits.putInt(iv, counterPos, counter);
					try {
						initCipherForDecrypt(cipher, iv);
						if (associatedData!=null && lenAD>0)
							cipher.updateAAD(associatedData, offAD, lenAD);
					} catch (InvalidKeyException | InvalidAlgorithmParameterException | NoSuchAlgorithmException | InvalidKeySpecException | NoSuchProviderException e) {
						throw new IOException(e);
					}
				}

				@Override
				public long currentPosition() {
					return pos;
				}

				@Override
				public boolean isClosed() {
					return closed;
				}

				@Override
				public void readFully(byte[] tab, int off, int len) throws IOException {
					//noinspection ResultOfMethodCallIgnored
					read(tab, off, len, true);
				}

				@Override
				public void close() {
					if (closed)
						return;
					closed=true;
				}

				@Deprecated
				@Override
				public String readLine() throws IOException {
					return new DataInputStream(this).readLine();
				}


			};
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | NoSuchProviderException e) {
			throw new IOException(e);
		}

		

	}
	@Override
	public abstract int getMaxBlockSizeForDecoding();
	@Override
	public int getOutputSizeForDecryption(int inputLen) throws InvalidKeyException, InvalidAlgorithmParameterException,
			NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
		initCipherForDecrypt(cipher, nullIV);
		if (includeIV()) {
			inputLen -= getIVSizeBytesWithoutExternalCounter();
		}

		int maxBlockSize = getMaxBlockSizeForDecoding();
		if (maxBlockSize == Integer.MAX_VALUE)
			return cipher.getOutputSize(inputLen);
		int div = inputLen / maxBlockSize;
		int mod = inputLen % maxBlockSize;
		int res = 0;
		if (div > 0)
			res += cipher.getOutputSize(maxBlockSize) * div;
		if (mod > 0)
			res += cipher.getOutputSize(mod);
		return res;
	}


	@Override
	public abstract void initCipherForDecrypt(AbstractCipher cipher, byte[] iv, byte[] externalCounter)
			throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException,
			InvalidKeySpecException, NoSuchProviderException;
	@Override
	public void initCipherForDecrypt(AbstractCipher cipher, byte[] iv) throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException
	{
		initCipherForDecrypt(cipher, iv, null);
	}
}

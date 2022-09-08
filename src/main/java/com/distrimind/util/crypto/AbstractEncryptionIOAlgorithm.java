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

import com.distrimind.util.io.*;

import javax.crypto.Cipher;
import java.io.IOException;

/**
 * 
 * @author Jason Mahdjoub
 * @version 5.0
 * @since Utils 1.5
 */
public abstract class AbstractEncryptionIOAlgorithm extends AbstractEncryptionOutputAlgorithm implements IEncryptionInputAlgorithm{
	private long lastAskedOutputSizeAfterDecryption, lastUsedSizeForEncryption=-1;
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
		return decode(bytes, off, len, null, 0, 0);
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
			if (len != bytes.length || off!=0)
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
		try (RandomByteArrayOutputStream baos = new RandomByteArrayOutputStream()) {
			this.decode(is, associatedData, offAD, lenAD, baos, externalCounter);
			return baos.getBytes();
		}
	}
	@Override
	public void decode(RandomInputStream is, byte[] associatedData, RandomOutputStream os) throws IOException
	{
		decode(is, associatedData, 0, associatedData==null?0:associatedData.length, os);
	}
	@Override
	public void decode(RandomInputStream is, RandomOutputStream os, byte[] externalCounter) throws IOException
	{
		decode(is, os, -1, externalCounter);
	}
	@Override
	public void decode(RandomInputStream is, RandomOutputStream os) throws IOException
	{
		decode(is, null, 0, 0, os);
	}
	@Override
	public void decode(RandomInputStream is, byte[] associatedData, int offAD, int lenAD, RandomOutputStream os) throws IOException
	{
		decode(is, associatedData, offAD, lenAD, os, null);
	}
	@Override
	public void decode(RandomInputStream is, byte[] associatedData, int offAD, int lenAD, RandomOutputStream os, byte[] externalCounter) throws IOException
	{
		decode(is, associatedData, offAD, lenAD, os, -1, externalCounter);
	}
	@Override
	public void decode(RandomInputStream is, RandomOutputStream os, int length) throws IOException
	{
		decode(is, null, 0, 0, os, length);
	}
	@Override
	public void decode(RandomInputStream is, RandomOutputStream os, int length, byte[] externalCounter) throws IOException
	{
		decode(is, null, 0, 0, os, length, externalCounter);
	}
	@Override
	public void decode(RandomInputStream is, byte[] associatedData, RandomOutputStream os, int length) throws IOException
	{
		decode(is, associatedData, 0, associatedData==null?0:associatedData.length, os, length);
	}

	@Override
	public void decode(RandomInputStream is, byte[] associatedData, int offAD, int lenAD, RandomOutputStream os, int length)
			throws IOException{
		decode(is, associatedData, offAD, lenAD, os, length, null);
	}
	
	protected byte[] readIV(RandomInputStream is, byte[] externalCounter) throws IOException
	{
		if (includeIV()) {
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
	public void decode(RandomInputStream is, byte[] associatedData, int offAD, int lenAD, RandomOutputStream os, int length, byte[] externalCounter)
			throws IOException{
		try(RandomInputStream in = getCipherInputStreamForDecryption(is, associatedData, offAD, lenAD, externalCounter))
		{
			in.transferTo(os, length);
		}
		os.flush();
	}

	@Override
	public RandomInputStream getCipherInputStreamForDecryption(final RandomInputStream is) throws IOException
	{
		return getCipherInputStreamForDecryption(is, null, 0, 0, null);
	}
	@Override
	public RandomInputStream getCipherInputStreamForDecryption(final RandomInputStream is, byte[] externalCounter) throws IOException
	{
		return getCipherInputStreamForDecryption(is, null, 0, 0, externalCounter);
	}

	@Override
	public RandomInputStream getCipherInputStreamForDecryption(final RandomInputStream is, final byte[] associatedData, final int offAD, final int lenAD) throws IOException
	{
		return getCipherInputStreamForDecryption(is, associatedData, offAD, lenAD, null);
	}
	protected abstract void initCipherForDecryptionWithIvAndCounter(AbstractCipher cipher, byte[] iv, int counter) throws IOException ;
	public abstract void initCipherForDecryptionWithIv(AbstractCipher cipher, byte[] iv) throws IOException ;
	protected byte[][] readIvsFromEncryptedStream(final RandomInputStream is, int headLengthBytes) throws IOException {
		if (includeIV()) {
			long l = is.length()-headLengthBytes;
			int nbIv = (int)((l / maxEncryptedPartLength) + (l % maxEncryptedPartLength > 0 ? 1 : 0));
			byte[][] res = new byte[nbIv][];
			for (int i = 0; i < nbIv; i++) {
				is.seek((long)i * (long)maxEncryptedPartLength+(long)headLengthBytes);
				res[i] = new byte[getIVSizeBytesWithoutExternalCounter()];
				is.readFully(res[i]);
			}
			return res;
		}
		else
			throw new IOException();
	}

	protected abstract boolean allOutputGeneratedIntoDoFinalFunction();

	@Override
	public RandomInputStream getCipherInputStreamForDecryption(final RandomInputStream is, final byte[] associatedData, final int offAD, final int lenAD, final byte[] externalCounter)
			throws IOException {
		checkKeysNotCleaned();
		final AbstractCipher cipher = getCipherInstance();


		CommonCipherInputStream res=new CommonCipherInputStream(allOutputGeneratedIntoDoFinalFunction(), maxEncryptedPartLength, is, includeIV(), iv, getIVSizeBytesWithoutExternalCounter(), getMaxExternalCounterLength(), externalCounter, cipher, associatedData, offAD, lenAD, super.finalizer.buffer, supportRandomEncryptionAndRandomDecryption(), getCounterStepInBytes(), maxPlainTextSizeForEncoding) {
			@Override
			protected void initCipherForDecryptionWithIvAndCounter(byte[] iv, int counter) throws IOException {
				AbstractEncryptionIOAlgorithm.this.initCipherForDecryptionWithIvAndCounter(cipher, iv, counter);
			}

			@Override
			protected void initCipherForDecryptionWithIv(byte[] iv) throws IOException {
				AbstractEncryptionIOAlgorithm.this.initCipherForDecryptionWithIv(cipher, iv);
			}

			@Override
			protected void initCipherForDecryption() throws IOException {
				AbstractEncryptionIOAlgorithm.this.initCipherForDecryption(cipher);
			}

			@Override
			protected long getOutputSizeAfterDecryption(long inputLength) throws IOException {
				return AbstractEncryptionIOAlgorithm.this.getOutputSizeAfterDecryption(inputLength);
			}

			@Override
			protected void checkKeysNotCleaned() {
				AbstractEncryptionIOAlgorithm.this.checkKeysNotCleaned();
			}

			@Override
			protected long getOutputSizeAfterEncryption(long length) throws IOException {
				return AbstractEncryptionIOAlgorithm.this.getOutputSizeAfterEncryption(lenAD);
			}
		};
		if (isUsingSideChannelMitigation())
			return getCPUUsageAsDecoyInputStream(res);
		else
			return res;
	}

	static long getOutputSizeAfterDecryption(AbstractCipher cipher, long inputLen, int maxEncryptedPartLength, int IVSizeBytesWithoutExternalCounter, int maxPlainTextSizeForEncoding) throws IOException {
		long add=inputLen % maxEncryptedPartLength;
		if (add>0) {
			add = cipher.getOutputSize((int) (add - IVSizeBytesWithoutExternalCounter));
		}
		return ((inputLen / maxEncryptedPartLength) * maxPlainTextSizeForEncoding)+add;
	}

	@Override
	public long getOutputSizeAfterDecryption(long inputLen) throws IOException {
		if (inputLen<0)
			throw new IllegalArgumentException();
		if (inputLen==0)
			return 0;
		if (inputLen==lastUsedSizeForEncryption)
			return lastAskedOutputSizeAfterDecryption;

		if (cipher.getMode()!= Cipher.DECRYPT_MODE) {
			if (includeIV() && mustAlterIVForOutputSizeComputation())
			{
				iv[0] = (byte) ~iv[0];
			}
			initCipherForDecryptionWithIv(cipher, iv);
		}
		lastUsedSizeForEncryption=inputLen;
		return lastAskedOutputSizeAfterDecryption=getOutputSizeAfterDecryption(cipher, inputLen, maxEncryptedPartLength,
				getIVSizeBytesWithoutExternalCounter(),maxPlainTextSizeForEncoding );
	}


	@Override
	public abstract void initCipherForDecryption(AbstractCipher cipher, byte[] iv, byte[] externalCounter)
			throws IOException;


}

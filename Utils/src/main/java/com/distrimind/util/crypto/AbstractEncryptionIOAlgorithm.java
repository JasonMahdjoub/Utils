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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import gnu.vm.jgnu.security.InvalidAlgorithmParameterException;
import gnu.vm.jgnu.security.InvalidKeyException;
import gnu.vm.jgnu.security.NoSuchAlgorithmException;
import gnu.vm.jgnu.security.NoSuchProviderException;
import gnu.vm.jgnu.security.spec.InvalidKeySpecException;
import gnu.vm.jgnux.crypto.BadPaddingException;
import gnu.vm.jgnux.crypto.IllegalBlockSizeException;
import gnu.vm.jgnux.crypto.NoSuchPaddingException;
import gnu.vm.jgnux.crypto.ShortBufferException;

/**
 * 
 * @author Jason Mahdjoub
 * @version 3.0
 * @since Utils 1.5
 */
public abstract class AbstractEncryptionIOAlgorithm extends AbstractEncryptionOutputAlgorithm {

	protected AbstractEncryptionIOAlgorithm(AbstractCipher cipher, int ivSizeBytes) {
		super(cipher, ivSizeBytes);

	}

	public byte[] decode(byte[] bytes)
			throws InvalidKeyException, InvalidAlgorithmParameterException, IOException, IllegalBlockSizeException,
			BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IllegalStateException, ShortBufferException {
		return decode(bytes, 0, bytes.length);
	}
	public byte[] decode(byte[] bytes, byte[] associatedData) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IOException, IllegalStateException, ShortBufferException
	{
		return decode(bytes, 0, bytes.length, associatedData, 0, associatedData.length);
	}
	public byte[] decode(byte[] bytes, int off, int len) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IOException, IllegalStateException, ShortBufferException
	{
		return decode(bytes, 0, bytes.length, null, 0, 0);
	}
	public byte[] decode(byte[] bytes, int off, int len, byte[] associatedData, int offAD, int lenAD)
			throws InvalidKeyException, InvalidAlgorithmParameterException, IOException, IllegalBlockSizeException,
			BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IllegalStateException, ShortBufferException {
		if (len < 0 || off < 0)
			throw new IllegalArgumentException("bytes.length=" + bytes.length + ", off=" + off + ", len=" + len);
		if (off > bytes.length)
			throw new IllegalArgumentException("bytes.length=" + bytes.length + ", off=" + off + ", len=" + len);
		if (off + len > bytes.length)
			throw new IllegalArgumentException("bytes.length=" + bytes.length + ", off=" + off + ", len=" + len);

		try (ByteArrayInputStream bais = new ByteArrayInputStream(bytes, off, len)) {
			return decode(bais, associatedData, offAD, lenAD);
		}
	}
	public byte[] decode(InputStream is, byte[] associatedData) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IOException, IllegalStateException, ShortBufferException
	{
		return decode(is, associatedData, 0, associatedData.length);
	}
	public byte[] decode(InputStream is) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IOException, IllegalStateException, ShortBufferException
	{
		return decode(is, null, 0, 0);
	}
	public byte[] decode(InputStream is, byte[] associatedData, int offAD, int lenAD)
			throws InvalidKeyException, InvalidAlgorithmParameterException, IOException, IllegalBlockSizeException,
			BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IllegalStateException, ShortBufferException {
		try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
			this.decode(is, associatedData, offAD, lenAD, baos);
			return baos.toByteArray();
		}
	}
	public void decode(InputStream is, byte[] associatedData, OutputStream os) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IOException, IllegalStateException, ShortBufferException
	{
		decode(is, associatedData, 0, associatedData.length, os);
	}
	public void decode(InputStream is, OutputStream os) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IOException, IllegalStateException, ShortBufferException
	{
		decode(is, null, 0, 0, os);
	}
	public void decode(InputStream is, byte[] associatedData, int offAD, int lenAD, OutputStream os) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IOException, IllegalStateException, ShortBufferException
	{
		decode(is, associatedData, offAD, lenAD, os, -1);
	}
	public void decode(InputStream is, OutputStream os, int length) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IOException, IllegalStateException, ShortBufferException
	{
		decode(is, null, 0, 0, os, length);
	}
	public void decode(InputStream is, byte[] associatedData, OutputStream os, int length) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IOException, IllegalStateException, ShortBufferException
	{
		decode(is, associatedData, 0, associatedData.length, os, length);
	}
	private byte iv[]=null;
	public void decode(InputStream is, byte[] associatedData, int offAD, int lenAD, OutputStream os, int length)
			throws InvalidKeyException, InvalidAlgorithmParameterException, IOException, IllegalBlockSizeException,
			BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IllegalStateException, ShortBufferException {
		byte[] iv = null;
		if (includeIV()) {
			if (this.iv==null)
				this.iv = new byte[getIVSizeBytes()];
			iv=this.iv;
			int read = is.read(this.iv);
			
			if (read != iv.length)
				throw new IOException("read=" + read + ", iv.length=" + iv.length);
		}

		initCipherForDecrypt(cipher, iv);
		if (associatedData!=null && lenAD>0)
			cipher.updateAAD(associatedData, offAD, lenAD);
		int maxBlockSize = getMaxBlockSizeForDecoding();
		int blockACC = 0;
		boolean finish = false;
		while (!finish) {
			
			int maxPartSize;
			if (length>=0)
				maxPartSize=Math.min(maxBlockSize, length);
			else 
				maxPartSize=maxBlockSize;
			
			blockACC = 0;
			do {
				int nb = Math.min(BUFFER_SIZE, maxPartSize - blockACC);
				int size = is.read(buffer, 0, nb);
				if (size > 0) {
					int sizeOut=cipher.update(buffer, 0, size, bufferOut, 0);
					if (sizeOut>0)
						os.write(bufferOut, 0, sizeOut);
					blockACC += size;
					if (length>=0)
						length-=size;
				}
				if (nb != size || size <= 0)
					finish = true;
			} while ((blockACC < maxPartSize || maxPartSize == Integer.MAX_VALUE) && !finish && length!=0);
			if (blockACC != 0)
				os.write(cipher.doFinal());
		}

		os.flush();

		/*
		 * try(CipherInputStream cis=new CipherInputStream(is, cipher)) { int read=-1;
		 * do { read=cis.read(); if (read!=-1) os.write(read); }while (read!=-1); }
		 */
	}

	public InputStream getCipherInputStream(InputStream is)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, IOException, InvalidKeySpecException, NoSuchProviderException {
		AbstractCipher c = getCipherInstance();
		byte[] iv = null;
		if (includeIV()) {
			iv = new byte[getIVSizeBytes()];
			if (is.read(iv) != iv.length)
				throw new IOException();
		}

		initCipherForDecrypt(c, iv);
		return c.getCipherInputStream(is);
	}

	public abstract int getMaxBlockSizeForDecoding();

	public int getOutputSizeForDecryption(int inputLen) throws InvalidKeyException, InvalidAlgorithmParameterException,
			NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
		initCipherForDecrypt(cipher, nullIV);
		if (includeIV()) {
			inputLen -= getIVSizeBytes();
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

	public abstract void initCipherForDecrypt(AbstractCipher cipher, byte[] iv)
			throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException,
			InvalidKeySpecException, NoSuchProviderException;

}

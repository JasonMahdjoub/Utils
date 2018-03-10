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

/**
 * 
 * @author Jason Mahdjoub
 * @version 3.0
 * @since Utils 1.5
 */
public abstract class AbstractEncryptionOutputAlgorithm {
	final static int BUFFER_SIZE = 1024;

	protected final AbstractCipher cipher;
	
	final byte nullIV[];
	
	protected AbstractEncryptionOutputAlgorithm(AbstractCipher cipher, int ivSizeBytes) {
		if (cipher == null)
			throw new NullPointerException("cipher");
		this.cipher = cipher;
		if (includeIV())
			nullIV = new byte[ivSizeBytes];
		else
			nullIV = null;
	}

	protected void initIV()
	{
		
	}
	
	public byte[] encode(byte[] bytes) throws gnu.vm.jgnu.security.InvalidKeyException, IOException,
			InvalidAlgorithmParameterException, gnu.vm.jgnux.crypto.BadPaddingException, IllegalStateException,
			gnu.vm.jgnux.crypto.IllegalBlockSizeException, NoSuchAlgorithmException, InvalidKeySpecException,
			NoSuchProviderException {
		return encode(bytes, 0, bytes.length);
	}
	public byte[] encode(byte[] bytes, byte[] associatedData) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalStateException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IOException 
	{
		return encode(bytes, 0, bytes.length, associatedData, 0, associatedData.length);
	}

	public byte[] encode(byte[] bytes, int off, int len) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalStateException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IOException 
	{
		return encode(bytes, off, len, null, 0, 0);
	}
	
			
	public byte[] encode(byte[] bytes, int off, int len, byte[] associatedData, int offAD, int lenAD) throws gnu.vm.jgnu.security.InvalidKeyException, IOException,
			InvalidAlgorithmParameterException, IllegalStateException, gnu.vm.jgnux.crypto.IllegalBlockSizeException,
			gnu.vm.jgnux.crypto.BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException,
			NoSuchProviderException {
		try (ByteArrayOutputStream baos = new ByteArrayOutputStream(getOutputSizeForEncryption(len))) {
			encode(bytes, off, len, associatedData, offAD, lenAD, baos);
			return baos.toByteArray();
		}
	}
	public void encode(byte[] bytes, int off, int len, OutputStream os) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalStateException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IOException 
	{
		encode(bytes, off, len, null,0, 0, os);
	}
	public void encode(byte[] bytes, int off, int len, byte[] associatedData, int offAD, int lenAD, OutputStream os) throws gnu.vm.jgnu.security.InvalidKeyException,
			IOException, InvalidAlgorithmParameterException, IllegalStateException,
			gnu.vm.jgnux.crypto.IllegalBlockSizeException, gnu.vm.jgnux.crypto.BadPaddingException,
			NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
		if (len < 0 || off < 0)
			throw new IllegalArgumentException("bytes.length=" + bytes.length + ", off=" + off + ", len=" + len);
		if (off > bytes.length)
			throw new IllegalArgumentException("bytes.length=" + bytes.length + ", off=" + off + ", len=" + len);
		if (off + len > bytes.length)
			throw new IllegalArgumentException("bytes.length=" + bytes.length + ", off=" + off + ", len=" + len);

		initCipherForEncrypt(cipher);
		if (associatedData!=null && lenAD>0)
			cipher.updateAAD(associatedData, offAD, lenAD);
		if (includeIV())
			os.write(cipher.getIV());
		int maxBlockSize = getMaxBlockSizeForEncoding();
		while (len > 0) {
			int size = 0;
			if (maxBlockSize == Integer.MAX_VALUE)
				size = len;
			else
				size = Math.min(len, maxBlockSize);

			os.write(cipher.doFinal(bytes, off, size));
			off += size;
			len -= size;
		}
		os.flush();

		/*
		 * try(CipherOutputStream cos=new CipherOutputStream(os, cipher)) {
		 * cos.write(bytes, off, len); }
		 */

	}
	public void encode(InputStream is, OutputStream os) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalStateException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IOException
	{
		encode(is, null, 0, 0, os);
	}
	public void encode(InputStream is, byte[] associatedData, OutputStream os) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalStateException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IOException 
	{
		encode(is, associatedData, 0, associatedData.length, os);
	}
	public void encode(InputStream is, byte[] associatedData, int offAD, int lenAD, OutputStream os) throws gnu.vm.jgnu.security.InvalidKeyException, IOException,InvalidAlgorithmParameterException, IllegalStateException, gnu.vm.jgnux.crypto.IllegalBlockSizeException,
	gnu.vm.jgnux.crypto.BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException,
	NoSuchProviderException{
		encode(is, associatedData, offAD, lenAD, os, -1);
	}
	public void encode(InputStream is, OutputStream os, int length) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalStateException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IOException
	{
		encode(is, null, 0, 0,os, length);
	}
	public void encode(InputStream is, byte[] associatedData, OutputStream os, int length) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalStateException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IOException
	{
		encode(is, associatedData, 0, associatedData.length, os, length);
	}
	public void encode(InputStream is, byte[] associatedData, int offAD, int lenAD, OutputStream os, int length) throws gnu.vm.jgnu.security.InvalidKeyException, IOException,
			InvalidAlgorithmParameterException, IllegalStateException, gnu.vm.jgnux.crypto.IllegalBlockSizeException,
			gnu.vm.jgnux.crypto.BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException,
			NoSuchProviderException {
		initCipherForEncrypt(cipher);
		if (associatedData!=null && lenAD>0)
			cipher.updateAAD(associatedData, offAD, lenAD);
		final int maxBlockSize=getMaxBlockSizeForEncoding();

		if (includeIV())
			os.write(cipher.getIV());
		byte[] buffer = new byte[BUFFER_SIZE];
		boolean finish = false;
		while (!finish) {
			int maxPartSize;
			if (length>=0)
				maxPartSize=Math.min(maxBlockSize, length);
			else 
				maxPartSize=maxBlockSize;
			
			int blockACC = 0;
			do {
				int nb = Math.min(BUFFER_SIZE, maxPartSize - blockACC);
				int size = is.read(buffer, 0, nb);
				if (size > 0) {
					byte[] tab=cipher.update(buffer, 0, size);
					if (tab!=null)
						os.write(tab);
					
					blockACC += size;
					if (length>=0)
						length-=blockACC;
				}
				if (nb != size || size <= 0)
					finish = true;
			} while ((blockACC < maxPartSize || maxPartSize == Integer.MAX_VALUE) && !finish && length!=0);
			if (blockACC != 0)
				os.write(cipher.doFinal());
		}

		os.flush();

		/*
		 * try(CipherOutputStream cos=new CipherOutputStream(os, cipher)) { int read=-1;
		 * do { read=is.read(); if (read!=-1) cos.write(read);
		 * 
		 * } while (read!=-1); }
		 */
	}

	protected abstract AbstractCipher getCipherInstance() throws gnu.vm.jgnu.security.NoSuchAlgorithmException,
			gnu.vm.jgnux.crypto.NoSuchPaddingException, NoSuchProviderException;

	public OutputStream getCipherOutputStream(OutputStream os) throws gnu.vm.jgnu.security.InvalidKeyException,
			gnu.vm.jgnu.security.NoSuchAlgorithmException, gnu.vm.jgnux.crypto.NoSuchPaddingException,
			InvalidAlgorithmParameterException, IOException, InvalidKeySpecException, NoSuchProviderException {
		AbstractCipher c = getCipherInstance();
		initCipherForEncrypt(c);
		if (includeIV())
			os.write(c.getIV());

		return c.getCipherOutputStream(os);
	}

	public abstract int getMaxBlockSizeForEncoding();

	
	public abstract int getIVSizeBytes();
	
	public int getOutputSizeForEncryption(int inputLen)
			throws gnu.vm.jgnu.security.InvalidKeyException, InvalidAlgorithmParameterException,
			NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
		initCipherForEncryptAndNotChangeIV(cipher);
		int maxBlockSize = getMaxBlockSizeForEncoding();
		if (maxBlockSize == Integer.MAX_VALUE) {
			if (includeIV()) {
				return cipher.getOutputSize(inputLen) + getIVSizeBytes();
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

	public abstract void initCipherForEncrypt(AbstractCipher cipher)
			throws gnu.vm.jgnu.security.InvalidKeyException, InvalidAlgorithmParameterException,
			NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException;

	public abstract void initCipherForEncryptAndNotChangeIV(AbstractCipher cipher)
			throws gnu.vm.jgnu.security.InvalidKeyException, InvalidAlgorithmParameterException,
			NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException;

}

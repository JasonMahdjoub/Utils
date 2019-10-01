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
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.*;


/**
 * 
 * @author Jason Mahdjoub
 * @version 5.0
 * @since Utils 1.7.0
 */
public class ServerASymmetricEncryptionAlgorithm implements IEncryptionInputAlgorithm {
	private static final int BUFFER_SIZE=AbstractEncryptionIOAlgorithm.BUFFER_SIZE;

	private final IServer server;
	public ServerASymmetricEncryptionAlgorithm(AbstractKeyPair myKeyPair) throws InvalidKeySpecException, InvalidKeyException, NoSuchProviderException, NoSuchAlgorithmException, NoSuchPaddingException {
		if (myKeyPair instanceof HybridASymmetricKeyPair)
			server=new HybridServer((HybridASymmetricKeyPair)myKeyPair);
		else
			server=new Server((ASymmetricKeyPair)myKeyPair);
	}


	@Override
	public int getMaxBlockSizeForDecoding() {
		return server.getMaxBlockSizeForDecoding();
	}

	public AbstractKeyPair getMyKeyPair() {
		if (server instanceof HybridServer)
			return ((HybridServer) server).myKeyPair;
		else
			return ((Server)server).getMyKeyPair();
	}
	@Override
	public int getOutputSizeForDecryption(int inputLen) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, InvalidAlgorithmParameterException {
		return server.getOutputSizeForDecryption(inputLen);
	}

	@Override
	public void initCipherForDecrypt(AbstractCipher cipher, byte[] iv, byte[] externalCounter) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, InvalidAlgorithmParameterException {
		server.initCipherForDecrypt(cipher, iv, externalCounter);
	}
	@Override
	public AbstractCipher getCipherInstance() throws NoSuchAlgorithmException, NoSuchPaddingException, NoSuchProviderException {
		return server.getCipherInstance();
	}
	@Override
	public boolean isPostQuantumEncryption() {
		return server.isPostQuantumEncryption();
	}
	@Override
	public void decode(InputStream is, byte[] associatedData, int offAD, int lenAD, OutputStream os, int length, byte[] externalCounter) throws InvalidKeyException, InvalidAlgorithmParameterException, IOException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IllegalStateException, ShortBufferException {
		server.decode(is, associatedData, offAD, lenAD, os, length, externalCounter);
	}
	@Override
	public InputStream getCipherInputStream(InputStream is, byte[] externalCounter) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidKeySpecException, NoSuchProviderException, IOException, InvalidAlgorithmParameterException {
		return server.getCipherInputStream(is, externalCounter);
	}

	static class HybridServer implements IServer
	{
		private final Server nonPQCEncryption, PQCEncryption;
		private final HybridASymmetricKeyPair myKeyPair;
		public HybridServer(HybridASymmetricKeyPair myKeyPair) throws InvalidKeySpecException, InvalidKeyException, NoSuchProviderException, NoSuchAlgorithmException, NoSuchPaddingException {
			this.nonPQCEncryption=new Server(myKeyPair.getNonPQCASymmetricKeyPair());
			this.PQCEncryption=new Server(myKeyPair.getPQCASymmetricKeyPair());
			this.myKeyPair=myKeyPair;
		}
		@Override
		public int getMaxBlockSizeForDecoding() {
			return Math.min(nonPQCEncryption.getMaxBlockSizeForDecoding(), PQCEncryption.getMaxBlockSizeForDecoding());
		}


		@Override
		public void initCipherForDecrypt(AbstractCipher cipher,byte[] iv, byte[] externalCounter)  {
			throw new IllegalAccessError();
		}

		@Override
		public AbstractCipher getCipherInstance()  {
			throw new IllegalAccessError();
		}



		@Override
		public boolean isPostQuantumEncryption() {
			return true;
		}

		@Override
		public int getOutputSizeForDecryption(int inputLen) throws InvalidKeyException,
				NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
			return PQCEncryption.getOutputSizeForDecryption(nonPQCEncryption.getOutputSizeForDecryption(inputLen));
		}

		static void privDecode(IServer PQCEncryption, IServer nonPQCEncryption, InputStream is, byte[] associatedData, int offAD, int lenAD, OutputStream os, int length, byte[] externalCounter)
				throws InvalidKeyException, InvalidAlgorithmParameterException, IOException, IllegalBlockSizeException,
				BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IllegalStateException, ShortBufferException
		{


			ByteArrayOutputStream baos=new ByteArrayOutputStream();
			PQCEncryption.decode(is, associatedData, offAD, lenAD, baos, length, externalCounter);

			byte []b=baos.toByteArray();

			os.write(nonPQCEncryption.decode(b, 0, b.length, associatedData, offAD, lenAD, externalCounter));


		}

		@Override
		public void decode(InputStream is, byte[] associatedData, int offAD, int lenAD, OutputStream os, int length, byte[] externalCounter)
				throws InvalidKeyException, InvalidAlgorithmParameterException, IOException, IllegalBlockSizeException,
				BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IllegalStateException, ShortBufferException
		{
			privDecode(PQCEncryption, nonPQCEncryption, is, associatedData, offAD, lenAD, os, length, externalCounter);
		}


		@Override
		public InputStream getCipherInputStream(final InputStream is, final byte[] externalCounter)
		{
			return getCipherInputStreamImpl(PQCEncryption, nonPQCEncryption, is, externalCounter);
		}

		static InputStream getCipherInputStreamImpl(final IServer PQCEncryption, final IServer nonPQCEncryption, final InputStream is, final byte[] externalCounter)
		{
			return new InputStream() {
				private byte[] decoded=null;
				private int index=0;
				private void checkDecoded() throws IOException {
					if (decoded==null)
					{
						ByteArrayOutputStream out=new ByteArrayOutputStream();
						try {
							privDecode(PQCEncryption, nonPQCEncryption,is, null, 0, 0, out, -1, externalCounter);
						} catch (InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException | NoSuchAlgorithmException | InvalidKeySpecException | NoSuchProviderException | ShortBufferException e) {
							throw new IOException(e);
						}
						decoded=out.toByteArray();
					}
				}
				@Override
				public int read() throws IOException {
					checkDecoded();
					if (index<decoded.length)
						return decoded[index++];
					else
						return -1;
				}

				@Override
				public int read(byte[] b, int off, int len) throws IOException {
					checkDecoded();
					if (index>=decoded.length)
						return -1;
					len=Math.min(decoded.length-index, len);
					System.arraycopy(decoded, index, b, off, len);
					return len;
				}
			};
		}


		@Override
		public byte[] decode(byte[] bytes, int off, int len, byte[] associatedData, int offAD, int lenAD, byte[] externalCounter)
				throws InvalidKeyException, InvalidAlgorithmParameterException, IOException, IllegalBlockSizeException,
				BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IllegalStateException, ShortBufferException {
			if (len < 0 || off < 0)
				throw new IllegalArgumentException("bytes.length=" + bytes.length + ", off=" + off + ", len=" + len);
			if (off > bytes.length)
				throw new IllegalArgumentException("bytes.length=" + bytes.length + ", off=" + off + ", len=" + len);
			if (off + len > bytes.length)
				throw new IllegalArgumentException("bytes.length=" + bytes.length + ", off=" + off + ", len=" + len);

			try (ByteArrayInputStream bais = new ByteArrayInputStream(bytes, off, len)) {
				return decode(bais, associatedData, offAD, lenAD, externalCounter);
			}
		}
		public byte[] decode(InputStream is, byte[] associatedData, int offAD, int lenAD, byte[] externalCounter)
				throws InvalidKeyException, InvalidAlgorithmParameterException, IOException, IllegalBlockSizeException,
				BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IllegalStateException, ShortBufferException {
			try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
				this.decode(is, associatedData, offAD, lenAD, baos, externalCounter);
				return baos.toByteArray();
			}
		}
		public void decode(InputStream is, byte[] associatedData, int offAD, int lenAD, OutputStream os, byte[] externalCounter) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IOException, IllegalStateException, ShortBufferException
		{
			decode(is, associatedData, offAD, lenAD, os, -1, externalCounter);
		}

	}


	private static class Server implements IServer{
		private final ASymmetricKeyPair myKeyPair;

		private final ASymmetricEncryptionType type;

		private final AbstractCipher cipher;

		private final int maxBlockSize;
		protected final byte[] buffer=new byte[BUFFER_SIZE];
		protected byte[] bufferOut;


		public Server(ASymmetricKeyPair myKeyPair)
				throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidKeySpecException,
				NoSuchProviderException {

			if (myKeyPair == null)
				throw new NullPointerException("myKeyPair");

			this.type = myKeyPair.getEncryptionAlgorithmType();
			this.myKeyPair = myKeyPair;
			cipher = type.getCipherInstance();
			cipher.init(Cipher.ENCRYPT_MODE, myKeyPair.getASymmetricPublicKey());
			maxBlockSize = cipher.getOutputSize(myKeyPair.getMaxBlockSize());
			initCipherForDecrypt(cipher, null, null);
		}


		@Override
		public AbstractCipher getCipherInstance() throws NoSuchAlgorithmException, NoSuchPaddingException, NoSuchProviderException {
			return type.getCipherInstance();
		}

		@Override
		public boolean isPostQuantumEncryption() {
			return myKeyPair.isPostQuantumKey();
		}

		@Override
		public int getMaxBlockSizeForDecoding() {
			return maxBlockSize;
		}


		public ASymmetricKeyPair getMyKeyPair() {
			return this.myKeyPair;
		}

		@Override
		public void initCipherForDecrypt(AbstractCipher _cipher, byte[] iv, byte[] externalCounter)
				throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
			_cipher.init(Cipher.DECRYPT_MODE, myKeyPair.getASymmetricPrivateKey());
		}


		@Override
		public void decode(InputStream is, byte[] associatedData, int offAD, int lenAD, OutputStream os, int length,  byte[] externalCounter)
				throws InvalidKeyException, InvalidAlgorithmParameterException, IOException, IllegalBlockSizeException,
				BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IllegalStateException, ShortBufferException {

			initCipherForDecrypt(cipher, null, externalCounter);
			if (associatedData!=null && lenAD>0)
				cipher.updateAAD(associatedData, offAD, lenAD);
			int maxBlockSize = getMaxBlockSizeForDecoding();
			int blockACC;
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



		@Override
		public InputStream getCipherInputStream(InputStream is, byte[] externalCounter)
				throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
				InvalidKeySpecException, NoSuchProviderException {
			AbstractCipher c = getCipherInstance();



			initCipherForDecrypt(c, null, externalCounter);
			return c.getCipherInputStream(is);
		}
		@Override
		public int getOutputSizeForDecryption(int inputLen) throws InvalidKeyException,
				NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
			initCipherForDecrypt(cipher, null, null);

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
		public byte[] decode(byte[] bytes, int off, int len, byte[] associatedData, int offAD, int lenAD, byte[] externalCounter)
				throws InvalidKeyException, InvalidAlgorithmParameterException, IOException, IllegalBlockSizeException,
				BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IllegalStateException, ShortBufferException {
			if (len < 0 || off < 0)
				throw new IllegalArgumentException("bytes.length=" + bytes.length + ", off=" + off + ", len=" + len);
			if (off > bytes.length)
				throw new IllegalArgumentException("bytes.length=" + bytes.length + ", off=" + off + ", len=" + len);
			if (off + len > bytes.length)
				throw new IllegalArgumentException("bytes.length=" + bytes.length + ", off=" + off + ", len=" + len);

			try (ByteArrayInputStream bais = new ByteArrayInputStream(bytes, off, len)) {
				return decode(bais, associatedData, offAD, lenAD, externalCounter);
			}
		}
		public byte[] decode(InputStream is, byte[] associatedData, int offAD, int lenAD, byte[] externalCounter)
				throws InvalidKeyException, InvalidAlgorithmParameterException, IOException, IllegalBlockSizeException,
				BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IllegalStateException, ShortBufferException {
			try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
				this.decode(is, associatedData, offAD, lenAD, baos, externalCounter);
				return baos.toByteArray();
			}
		}
		public void decode(InputStream is, byte[] associatedData, int offAD, int lenAD, OutputStream os, byte[] externalCounter) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IOException, IllegalStateException, ShortBufferException
		{
			decode(is, associatedData, offAD, lenAD, os, -1, externalCounter);
		}
	}




	@Override
	public byte[] decode(byte[] bytes)
			throws InvalidKeyException, InvalidAlgorithmParameterException, IOException, IllegalBlockSizeException,
			BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IllegalStateException, ShortBufferException {
		return decode(bytes, 0, bytes.length);
	}
	@Override
	public byte[] decode(byte[] bytes, byte[] associatedData, byte[] externalCounter) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IOException, IllegalStateException, ShortBufferException
	{
		return decode(bytes, 0, bytes.length, associatedData, 0, associatedData==null?0:associatedData.length, externalCounter);
	}
	@Override
	public byte[] decode(byte[] bytes, byte[] associatedData) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IOException, IllegalStateException, ShortBufferException
	{
		return decode(bytes, associatedData, null);
	}
	@Override
	public byte[] decode(byte[] bytes, int off, int len) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IOException, IllegalStateException, ShortBufferException
	{
		return decode(bytes, 0, bytes.length, null, 0, 0);
	}
	@Override
	public byte[] decode(byte[] bytes, int off, int len, byte[] associatedData, int offAD, int lenAD) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IllegalStateException, ShortBufferException, IOException
	{
		return decode(bytes, off, len, associatedData, offAD, lenAD, null);
	}
	@Override
	public byte[] decode(byte[] bytes, int off, int len, byte[] associatedData, int offAD, int lenAD, byte[] externalCounter)
			throws InvalidKeyException, InvalidAlgorithmParameterException, IOException, IllegalBlockSizeException,
			BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IllegalStateException, ShortBufferException {
		if (len < 0 || off < 0)
			throw new IllegalArgumentException("bytes.length=" + bytes.length + ", off=" + off + ", len=" + len);
		if (off > bytes.length)
			throw new IllegalArgumentException("bytes.length=" + bytes.length + ", off=" + off + ", len=" + len);
		if (off + len > bytes.length)
			throw new IllegalArgumentException("bytes.length=" + bytes.length + ", off=" + off + ", len=" + len);

		try (ByteArrayInputStream bais = new ByteArrayInputStream(bytes, off, len)) {
			return decode(bais, associatedData, offAD, lenAD, externalCounter);
		}
	}
	@Override
	public byte[] decode(InputStream is, byte[] associatedData) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IOException, IllegalStateException, ShortBufferException
	{
		return decode(is, associatedData, 0, associatedData==null?0:associatedData.length);
	}
	@Override
	public byte[] decode(InputStream is) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IOException, IllegalStateException, ShortBufferException
	{
		return decode(is, null, 0, 0);
	}
	@Override
	public byte[] decode(InputStream is, byte[] associatedData, int offAD, int lenAD) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IllegalStateException, ShortBufferException, IOException
	{
		return decode(is, associatedData, offAD, lenAD, (byte[])null);
	}
	@Override
	public byte[] decode(InputStream is, byte[] associatedData, int offAD, int lenAD, byte[] externalCounter)
			throws InvalidKeyException, InvalidAlgorithmParameterException, IOException, IllegalBlockSizeException,
			BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IllegalStateException, ShortBufferException {
		try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
			this.decode(is, associatedData, offAD, lenAD, baos, externalCounter);
			return baos.toByteArray();
		}
	}
	@Override
	public void decode(InputStream is, byte[] associatedData, OutputStream os) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IOException, IllegalStateException, ShortBufferException
	{
		decode(is, associatedData, 0, associatedData==null?0:associatedData.length, os);
	}
	@Override
	public void decode(InputStream is, OutputStream os, byte[] externalCounter) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IOException, IllegalStateException, ShortBufferException
	{
		decode(is, os, -1, externalCounter);
	}
	@Override
	public void decode(InputStream is, OutputStream os) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IOException, IllegalStateException, ShortBufferException
	{
		decode(is, null, 0, 0, os);
	}
	@Override
	public void decode(InputStream is, byte[] associatedData, int offAD, int lenAD, OutputStream os) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IOException, IllegalStateException, ShortBufferException
	{
		decode(is, associatedData, offAD, lenAD, os, null);
	}
	@Override
	public void decode(InputStream is, byte[] associatedData, int offAD, int lenAD, OutputStream os, byte[] externalCounter) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IOException, IllegalStateException, ShortBufferException
	{
		decode(is, associatedData, offAD, lenAD, os, -1, externalCounter);
	}
	@Override
	public void decode(InputStream is, OutputStream os, int length) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IOException, IllegalStateException, ShortBufferException
	{
		decode(is, null, 0, 0, os, length);
	}
	@Override
	public void decode(InputStream is, OutputStream os, int length, byte[] externalCounter) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IOException, IllegalStateException, ShortBufferException
	{
		decode(is, null, 0, 0, os, length, externalCounter);
	}
	@Override
	public void decode(InputStream is, byte[] associatedData, OutputStream os, int length) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IOException, IllegalStateException, ShortBufferException
	{
		decode(is, associatedData, 0, associatedData==null?0:associatedData.length, os, length);
	}

	@Override
	public void decode(InputStream is, byte[] associatedData, int offAD, int lenAD, OutputStream os, int length)
			throws InvalidKeyException, InvalidAlgorithmParameterException, IOException, IllegalBlockSizeException,
			BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IllegalStateException, ShortBufferException {
		decode(is, associatedData, offAD, lenAD, os, length, null);
	}

	@Override
	public InputStream getCipherInputStream(InputStream is)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			InvalidKeySpecException, NoSuchProviderException, IOException, InvalidAlgorithmParameterException {
		return getCipherInputStream(is, null);
	}
	@Override
	public void initCipherForDecrypt(AbstractCipher cipher) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, InvalidAlgorithmParameterException {
		initCipherForDecrypt(cipher,null,  null);
	}

	@Override
	public void initCipherForDecrypt(AbstractCipher cipher, byte[] iv) throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException
	{
		initCipherForDecrypt(cipher,iv,  null);
	}

}

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
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;


/**
 * 
 * @author Jason Mahdjoub
 * @version 5.0
 * @since Utils 1.7.0
 */
public class ServerASymmetricEncryptionAlgorithm implements IEncryptionInputAlgorithm {
	private static final int BUFFER_SIZE=AbstractEncryptionIOAlgorithm.BUFFER_SIZE;

	private final IServer server;
	public ServerASymmetricEncryptionAlgorithm(AbstractKeyPair<?, ?> myKeyPair) throws IOException {
		if (myKeyPair instanceof HybridASymmetricKeyPair)
			server=new HybridServer((HybridASymmetricKeyPair)myKeyPair);
		else
			server=new Server((ASymmetricKeyPair)myKeyPair);
	}
	public ServerASymmetricEncryptionAlgorithm(IASymmetricPrivateKey myPrivateKey) throws IOException {
		if (myPrivateKey instanceof HybridASymmetricPrivateKey)
			server=new HybridServer((HybridASymmetricPrivateKey)myPrivateKey);
		else
			server=new Server((ASymmetricPrivateKey) myPrivateKey);
	}


	@Override
	public int getMaxPlainTextSizeForEncoding() {
		return server.getMaxPlainTextSizeForEncoding();
	}

	public IASymmetricPrivateKey getMyKeyPair() {
		if (server instanceof HybridServer)
			return ((HybridServer) server).myPrivateKey;
		else
			return ((Server)server).getMyKeyPair();
	}
	@Override
	public long getOutputSizeForDecryption(long inputLen) throws IOException {
		return server.getOutputSizeForDecryption(inputLen);
	}

	@Override
	public void initCipherForDecrypt(AbstractCipher cipher, byte[] iv, byte[] externalCounter) throws IOException {
		server.initCipherForDecrypt(cipher, iv, externalCounter);
	}
	@Override
	public AbstractCipher getCipherInstance() throws IOException {
		return server.getCipherInstance();
	}
	@Override
	public boolean isPostQuantumEncryption() {
		return server.isPostQuantumEncryption();
	}
	@Override
	public void decode(RandomInputStream is, byte[] associatedData, int offAD, int lenAD, RandomOutputStream os, int length, byte[] externalCounter) throws IOException {
		server.decode(is, associatedData, offAD, lenAD, os, length, externalCounter);
	}
	@Override
	public RandomInputStream getCipherInputStream(RandomInputStream is, byte[] associatedData, int offAD, int lenAD, byte[] externalCounter) throws IOException {
		return server.getCipherInputStream(is, associatedData, offAD, lenAD, externalCounter);
	}
	@Override
	public RandomInputStream getCipherInputStream(RandomInputStream is, byte[] externalCounter) throws IOException {
		return server.getCipherInputStream(is, externalCounter);
	}

	@Override
	public RandomInputStream getCipherInputStream(RandomInputStream is, byte[] associatedData, int offAD, int lenAD) throws IOException {
		return server.getCipherInputStream(is, associatedData, offAD, lenAD, null);
	}

	static class HybridServer implements IServer
	{
		private final Server nonPQCEncryption, PQCEncryption;
		private final HybridASymmetricPrivateKey myPrivateKey;
		public HybridServer(HybridASymmetricKeyPair myKeyPair) throws IOException {
			this(myKeyPair.getASymmetricPrivateKey());
		}
		public HybridServer(HybridASymmetricPrivateKey myPrivateKey) throws IOException{
			this.nonPQCEncryption=new Server(myPrivateKey.getNonPQCPrivateKey());
			this.PQCEncryption=new Server(myPrivateKey.getPQCPrivateKey());
			this.myPrivateKey=myPrivateKey;
		}
		@Override
		public int getMaxPlainTextSizeForEncoding() {
			return Math.min(nonPQCEncryption.getMaxPlainTextSizeForEncoding(), PQCEncryption.getMaxPlainTextSizeForEncoding());
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
		public long getOutputSizeForDecryption(long inputLen) throws IOException {
			return PQCEncryption.getOutputSizeForDecryption(nonPQCEncryption.getOutputSizeForDecryption(inputLen));
		}

		/*static void privDecode(IServer PQCEncryption, IServer nonPQCEncryption, RandomInputStream is, byte[] associatedData, int offAD, int lenAD, RandomOutputStream os, byte[] externalCounter)
				throws IOException
		{


			RandomByteArrayOutputStream baos=new RandomByteArrayOutputStream();
			PQCEncryption.decode(is, associatedData, offAD, lenAD, baos, externalCounter);

			byte []b=baos.getBytes();

			os.write(nonPQCEncryption.decode(b, 0, b.length, associatedData, offAD, lenAD, externalCounter));


		}*/

		@Override
		public void decode(RandomInputStream is, byte[] associatedData, int offAD, int lenAD, RandomOutputStream os, int length, byte[] externalCounter) throws IOException {
			try(RandomInputStream in = getCipherInputStream(is, externalCounter))
			{
				in.transferTo(os, length);
			}
			os.flush();
		}


		@Override
		public RandomInputStream getCipherInputStream(final RandomInputStream is, final byte[] externalCounter) throws IOException {
			return getCipherInputStreamImpl(PQCEncryption, nonPQCEncryption, is, null, 0, 0, externalCounter);
		}
		@Override
		public RandomInputStream getCipherInputStream(final RandomInputStream is, byte[] associatedData, int offAD, int lenAD, final byte[] externalCounter) throws IOException {
			return getCipherInputStreamImpl(PQCEncryption, nonPQCEncryption, is, associatedData, offAD, lenAD, externalCounter);
		}

		static RandomInputStream getCipherInputStreamImpl(final IServer PQCEncryption, final IServer nonPQCEncryption, final RandomInputStream is, byte[] associatedData, int offAD, int lenAD, final byte[] externalCounter) throws IOException {
			return nonPQCEncryption.getCipherInputStream(PQCEncryption.getCipherInputStream(is, associatedData, offAD, lenAD, externalCounter), associatedData, offAD, lenAD, externalCounter);
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
		public byte[] decode(RandomInputStream is, byte[] associatedData, int offAD, int lenAD, byte[] externalCounter)
				throws IOException {
			try (RandomByteArrayOutputStream baos = new RandomByteArrayOutputStream()) {
				this.decode(is, associatedData, offAD, lenAD, baos, -1, externalCounter);
				return baos.getBytes();
			}
		}


	}


	private static class Server implements IServer{
		private final ASymmetricPrivateKey myPrivateKey;

		private final ASymmetricEncryptionType type;

		private final AbstractCipher cipher;

		private final int maxPlainTextSizeForEncoding;
		protected final byte[] buffer=new byte[BUFFER_SIZE];
		private final int maxEncryptedPartLength;

		public Server(ASymmetricKeyPair myKeyPair)
				throws IOException {
			this(myKeyPair.getASymmetricPrivateKey());
		}
		public Server(ASymmetricPrivateKey myPrivateKey)
				throws IOException {

			if (myPrivateKey == null)
				throw new NullPointerException("myKeyPair");
			try {
				this.type = myPrivateKey.getEncryptionAlgorithmType();
				this.myPrivateKey = myPrivateKey;
				cipher = type.getCipherInstance();
				cipher.init(Cipher.DECRYPT_MODE, myPrivateKey);
				maxPlainTextSizeForEncoding = myPrivateKey.getMaxBlockSize();
				maxEncryptedPartLength = cipher.getOutputSize(maxPlainTextSizeForEncoding);
				initCipherForDecrypt(cipher, null, null);
			} catch (NoSuchAlgorithmException | InvalidKeyException | InvalidKeySpecException | NoSuchPaddingException | NoSuchProviderException e) {
				throw new IOException();
			}

		}


		@Override
		public AbstractCipher getCipherInstance() throws IOException {
			try {
				return type.getCipherInstance();
			} catch (NoSuchAlgorithmException | NoSuchPaddingException | NoSuchProviderException e) {
				throw new IOException(e);
			}
		}

		@Override
		public boolean isPostQuantumEncryption() {
			return myPrivateKey.isPostQuantumKey();
		}

		@Override
		public int getMaxPlainTextSizeForEncoding() {
			return maxPlainTextSizeForEncoding;
		}


		public ASymmetricPrivateKey getMyKeyPair() {
			return this.myPrivateKey;
		}

		@Override
		public void initCipherForDecrypt(AbstractCipher _cipher, byte[] iv, byte[] externalCounter)
				throws IOException {
			try {
				_cipher.init(Cipher.DECRYPT_MODE, myPrivateKey);
			} catch (InvalidKeyException | NoSuchAlgorithmException | InvalidKeySpecException | NoSuchProviderException e) {
				throw new IOException();
			}
		}


		@Override
		public void decode(RandomInputStream is, byte[] associatedData, int offAD, int lenAD, RandomOutputStream os, int length,  byte[] externalCounter)
				throws IOException {
			try(RandomInputStream in = getCipherInputStream(is, associatedData, offAD, lenAD, externalCounter))
			{
				in.transferTo(os, length);
			}
			os.flush();
		}

		@Override
		public RandomInputStream getCipherInputStream(final RandomInputStream is,  final byte[] externalCounter) throws IOException {
			return getCipherInputStream(is, null, 0, 0, externalCounter);
		}
		@Override
		public RandomInputStream getCipherInputStream(final RandomInputStream is,  byte[] associatedData, int offAD, int lenAD, final byte[] externalCounter)
				throws IOException {

			return new CommonCipherInputStream(maxEncryptedPartLength, is, false, null, 0, false, externalCounter, cipher, associatedData, offAD, lenAD, buffer, false, 0, maxPlainTextSizeForEncoding) {
				@Override
				protected void initCipherForDecryptionWithIvAndCounter(byte[] iv, int counter) throws IOException {
					Server.this.initCipherForDecrypt(cipher, iv, externalCounter);
				}

				@Override
				protected void initCipherForDecrypt() throws IOException {
					Server.this.initCipherForDecrypt(cipher, null, externalCounter);
				}
			};
		}
		@Override
		public long getOutputSizeForDecryption(long inputLen) throws IOException {
			if (inputLen<0)
				throw new IllegalArgumentException();
			if (inputLen==0)
				return 0;
			if (cipher.getMode()!=Cipher.DECRYPT_MODE)
				initCipherForDecrypt(cipher, null, null);
			return AbstractEncryptionIOAlgorithm.getOutputSizeForDecryption(cipher, inputLen, maxEncryptedPartLength,
					0,maxPlainTextSizeForEncoding );
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
		public byte[] decode(RandomInputStream is, byte[] associatedData, int offAD, int lenAD, byte[] externalCounter)
				throws IOException {
			try (RandomByteArrayOutputStream baos = new RandomByteArrayOutputStream()) {
				this.decode(is, associatedData, offAD, lenAD, baos, externalCounter);
				return baos.getBytes();
			}
		}
		public void decode(RandomInputStream is, byte[] associatedData, int offAD, int lenAD, RandomOutputStream os, byte[] externalCounter) throws IOException
		{
			decode(is, associatedData, offAD, lenAD, os, -1, externalCounter);
		}
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
			throws IOException {
		decode(is, associatedData, offAD, lenAD, os, length, null);
	}

	@Override
	public RandomInputStream getCipherInputStream(RandomInputStream is)
			throws IOException {
		return getCipherInputStream(is, null);
	}
	@Override
	public void initCipherForDecrypt(AbstractCipher cipher) throws IOException {
		initCipherForDecrypt(cipher,null,  null);
	}

	@Override
	public void initCipherForDecrypt(AbstractCipher cipher, byte[] iv) throws IOException
	{
		initCipherForDecrypt(cipher,iv,  null);
	}

}

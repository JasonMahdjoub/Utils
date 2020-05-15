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

import javax.crypto.*;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;

/**
 * 
 * @author Jason Mahdjoub
 * @version 5.0
 * @since Utils 1.7
 */
public class ClientASymmetricEncryptionAlgorithm extends AbstractEncryptionOutputAlgorithm {

	private final AbstractEncryptionOutputAlgorithm client;

	public ClientASymmetricEncryptionAlgorithm(AbstractSecureRandom random, IASymmetricPublicKey distantPublicKey) throws NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidKeyException, InvalidKeySpecException, NoSuchProviderException, InvalidAlgorithmParameterException {
		super();
		if (distantPublicKey instanceof HybridASymmetricPublicKey)
			client=new HybridClient(random, (HybridASymmetricPublicKey)distantPublicKey);
		else
			client=new Client(random, (ASymmetricPublicKey)distantPublicKey);
	}

	private static class HybridClient extends AbstractEncryptionOutputAlgorithm {
		private final Client nonPQCEncryption, PQCEncryption;
		private final HybridASymmetricPublicKey hybridASymmetricPublicKey;
		public HybridClient(AbstractSecureRandom random, HybridASymmetricPublicKey distantPublicKey) throws NoSuchAlgorithmException, NoSuchPaddingException,
				InvalidKeyException, InvalidKeySpecException, NoSuchProviderException, InvalidAlgorithmParameterException {
			super();
			this.nonPQCEncryption=new Client(random, distantPublicKey.getNonPQCPublicKey());
			this.PQCEncryption=new Client(random, distantPublicKey.getPQCPublicKey());
			this.hybridASymmetricPublicKey=distantPublicKey;
		}

		@Override
		protected AbstractCipher getCipherInstance()  {
			throw new IllegalAccessError();
		}

		@Override
		public int getPlanTextSizeForEncoding() {
			return Math.min(nonPQCEncryption.getPlanTextSizeForEncoding(), PQCEncryption.getPlanTextSizeForEncoding());
		}

		@Override
		public int getIVSizeBytesWithExternalCounter() {
			return Math.max(nonPQCEncryption.getIVSizeBytesWithExternalCounter(), PQCEncryption.getIVSizeBytesWithExternalCounter());
		}

		@Override
		protected boolean includeIV() {
			return false;
		}

		@Override
		public void initCipherForEncrypt(AbstractCipher cipher, byte[] externalCounter) {
			throw new IllegalAccessError();
		}

		@Override
		public void initCipherForEncryptWithNullIV(AbstractCipher cipher) {
			throw new IllegalAccessError();
		}

		@Override
		public boolean isPostQuantumEncryption() {
			return true;
		}


		@Override
		public long getOutputSizeForEncryption(long inputLen) throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
			return nonPQCEncryption.getOutputSizeForEncryption(PQCEncryption.getOutputSizeForEncryption(inputLen));
		}




		@Override
		public void encode(byte[] bytes, int off, int len, byte[] associatedData, int offAD, int lenAD, OutputStream os, byte[] externalCounter) throws InvalidKeyException,
				IOException, InvalidAlgorithmParameterException, IllegalStateException,
				IllegalBlockSizeException, BadPaddingException,
				NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
			ByteArrayOutputStream baos=new ByteArrayOutputStream();
			nonPQCEncryption.encode(bytes, off, len, associatedData, offAD, lenAD, baos, externalCounter);
			byte[] b=baos.toByteArray();
			PQCEncryption.encode(b, 0, b.length, associatedData, offAD, lenAD, os, externalCounter);
		}
		private final byte[] buffer=new byte[4096];

		@Override
		public void encode(InputStream is, byte[] associatedData, int offAD, int lenAD, OutputStream os, int length, byte[] externalCounter) throws InvalidKeyException, IOException,
				InvalidAlgorithmParameterException, IllegalStateException, IllegalBlockSizeException,
				BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException,
				NoSuchProviderException, ShortBufferException {
			for(;;) {
				ByteArrayOutputStream baos=new ByteArrayOutputStream();
				int nb=is.read(buffer);
				if (nb<0)
					break;
				nonPQCEncryption.encode(buffer, 0, nb, associatedData, offAD, lenAD, baos, externalCounter);
				byte[] b=baos.toByteArray();
				PQCEncryption.encode(b, 0, b.length, associatedData, offAD, lenAD, os, externalCounter);

			}
		}

		@Override
		public OutputStream getCipherOutputStream(final OutputStream os, final byte[] externalCounter) {
			return new OutputStream() {
				private final byte[] one=new byte[1];
				@Override
				public void write(int b) throws IOException {
					one[0]=(byte)b;
					write(one);
				}

				@Override
				public void write(byte[] b, int off, int len) throws IOException {
					try {
						encode(b, off, len, null, 0, 0, os, externalCounter);
					} catch (InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException | NoSuchAlgorithmException | InvalidKeySpecException | NoSuchProviderException e) {
						throw new IOException(e);
					}
				}
			};
		}
	}

	@Override
	public byte getBlockModeCounterBytes() {
		return client.getBlockModeCounterBytes();
	}

	@Override
	public boolean useExternalCounter() {
		return client.useExternalCounter();
	}

	@Override
	public void initBufferAllocatorArgs() {
		client.initBufferAllocatorArgs();
	}

	@Override
	public byte[] encode(byte[] bytes) throws InvalidKeyException, IOException, InvalidAlgorithmParameterException, BadPaddingException, IllegalStateException, IllegalBlockSizeException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
		return client.encode(bytes);
	}

	@Override
	public byte[] encode(byte[] bytes, byte[] associatedData) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalStateException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IOException {
		return client.encode(bytes, associatedData);
	}

	@Override
	public byte[] encode(byte[] bytes, byte[] associatedData, byte[] externalCounter) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalStateException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IOException {
		return client.encode(bytes, associatedData, externalCounter);
	}

	@Override
	public byte[] encode(byte[] bytes, int off, int len) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalStateException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IOException {
		return client.encode(bytes, off, len);
	}

	@Override
	public byte[] encode(byte[] bytes, int off, int len, byte[] associatedData, int offAD, int lenAD) throws InvalidKeyException, IOException, InvalidAlgorithmParameterException, IllegalStateException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
		return client.encode(bytes, off, len, associatedData, offAD, lenAD);
	}

	@Override
	public byte[] encode(byte[] bytes, int off, int len, byte[] associatedData, int offAD, int lenAD, byte[] externalCounter) throws InvalidKeyException, IOException, InvalidAlgorithmParameterException, IllegalStateException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
		return client.encode(bytes, off, len, associatedData, offAD, lenAD, externalCounter);
	}

	@Override
	public void encode(byte[] bytes, int off, int len, OutputStream os) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalStateException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IOException {
		client.encode(bytes, off, len, os);
	}

	@Override
	public void encode(byte[] bytes, int off, int len, byte[] associatedData, int offAD, int lenAD, OutputStream os) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalStateException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IOException {
		client.encode(bytes, off, len, associatedData, offAD, lenAD, os);
	}

	@Override
	public void encode(byte[] bytes, int off, int len, byte[] associatedData, int offAD, int lenAD, OutputStream os, byte[] externalCounter) throws InvalidKeyException, IOException, InvalidAlgorithmParameterException, IllegalStateException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
		client.encode(bytes, off, len, associatedData, offAD, lenAD, os, externalCounter);
	}

	@Override
	public void encode(InputStream is, OutputStream os) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalStateException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IOException, ShortBufferException {
		client.encode(is, os);
	}

	@Override
	public void encode(InputStream is, byte[] associatedData, OutputStream os) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalStateException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IOException, ShortBufferException {
		client.encode(is, associatedData, os);
	}

	@Override
	public void encode(InputStream is, byte[] associatedData, int offAD, int lenAD, OutputStream os) throws InvalidKeyException, IOException, InvalidAlgorithmParameterException, IllegalStateException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, ShortBufferException {
		client.encode(is, associatedData, offAD, lenAD, os);
	}

	@Override
	public void encode(InputStream is, OutputStream os, int length) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalStateException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IOException, ShortBufferException {
		client.encode(is, os, length);
	}

	@Override
	public void encode(InputStream is, byte[] associatedData, OutputStream os, int length) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalStateException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IOException, ShortBufferException {
		client.encode(is, associatedData, os, length);
	}

	@Override
	public void encode(InputStream is, byte[] associatedData, int offAD, int lenAD, OutputStream os, int length) throws InvalidKeyException, IOException, InvalidAlgorithmParameterException, IllegalStateException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, ShortBufferException {
		client.encode(is, associatedData, offAD, lenAD, os, length);
	}

	@Override
	public void encode(InputStream is, byte[] associatedData, int offAD, int lenAD, OutputStream os, int length, byte[] externalCounter) throws InvalidKeyException, IOException, InvalidAlgorithmParameterException, IllegalStateException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, ShortBufferException {
		client.encode(is, associatedData, offAD, lenAD, os, length, externalCounter);
	}

	@Override
	public AbstractCipher getCipherInstance() throws NoSuchAlgorithmException, NoSuchPaddingException, NoSuchProviderException {
		return client.getCipherInstance();
	}

	@Override
	public OutputStream getCipherOutputStream(OutputStream os, byte[] externalCounter) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, IOException, InvalidKeySpecException, NoSuchProviderException {
		return client.getCipherOutputStream(os, externalCounter);
	}

	@Override
	public int getPlanTextSizeForEncoding() {
		return client.getPlanTextSizeForEncoding();
	}

	@Override
	public int getIVSizeBytesWithExternalCounter() {
		return client.getIVSizeBytesWithExternalCounter();
	}

	@Override
	public long getOutputSizeForEncryption(long inputLen) throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
		return client.getOutputSizeForEncryption(inputLen);
	}

	@Override
	public boolean includeIV() {
		return client.includeIV();
	}

	@Override
	public void initCipherForEncrypt(AbstractCipher cipher) throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
		client.initCipherForEncrypt(cipher);
	}

	@Override
	public void initCipherForEncrypt(AbstractCipher cipher, byte[] externalCounter) throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
		client.initCipherForEncrypt(cipher, externalCounter);
	}

	@Override
	public void initCipherForEncryptWithNullIV(AbstractCipher cipher) throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
		client.initCipherForEncryptWithNullIV(cipher);
	}

	@Override
	public boolean isPostQuantumEncryption() {
		return client.isPostQuantumEncryption();
	}

	public IASymmetricPublicKey getDistantPublicKey() {
		if (this.client instanceof Client)
			return ((Client)client).getDistantPublicKey();
		else
			return ((HybridClient)client).hybridASymmetricPublicKey;
	}
	private static class Client extends AbstractEncryptionOutputAlgorithm {
		private final ASymmetricPublicKey distantPublicKey;

		private final ASymmetricEncryptionType type;

		private final int maxBlockSize;
		private final AbstractSecureRandom random;

		public Client(AbstractSecureRandom random, ASymmetricPublicKey distantPublicKey) throws NoSuchAlgorithmException, NoSuchPaddingException,
				InvalidKeyException, InvalidKeySpecException, NoSuchProviderException, InvalidAlgorithmParameterException {
			super(distantPublicKey.getEncryptionAlgorithmType().getCipherInstance(), 0);
			this.type = distantPublicKey.getEncryptionAlgorithmType();
			this.distantPublicKey = distantPublicKey;
			this.random = random;
			this.maxBlockSize = distantPublicKey.getMaxBlockSize();
			initCipherForEncrypt(this.cipher);
			initBufferAllocatorArgs();
		}

		@Override
		public boolean isPostQuantumEncryption() {
			return distantPublicKey.isPostQuantumKey();
		}

		@Override
		protected AbstractCipher getCipherInstance() throws NoSuchAlgorithmException, NoSuchPaddingException, NoSuchProviderException {
			return type.getCipherInstance();
		}

		public ASymmetricPublicKey getDistantPublicKey() {
			return this.distantPublicKey;
		}

		@Override
		public int getPlanTextSizeForEncoding() {
			return maxBlockSize;
		}

		@Override
		protected boolean includeIV() {
			return false;
		}

		@Override
		public void initCipherForEncrypt(AbstractCipher _cipher, byte[] externalCounter)
				throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException {
			initCipherForEncryptWithNullIV(_cipher);
		}

		@Override
		public void initCipherForEncryptWithNullIV(AbstractCipher _cipher)
				throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException {
			_cipher.init(Cipher.ENCRYPT_MODE, distantPublicKey, random);

		}


		@Override
		public int getIVSizeBytesWithExternalCounter() {
			return 0;
		}
	}
}

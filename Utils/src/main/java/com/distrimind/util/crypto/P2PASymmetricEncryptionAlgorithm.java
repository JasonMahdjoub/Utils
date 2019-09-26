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
 * @version 3.0
 * @since Utils 1.4
 */
public class P2PASymmetricEncryptionAlgorithm extends AbstractEncryptionIOAlgorithm {

	private final AbstractEncryptionIOAlgorithm p2pencryption;

	public P2PASymmetricEncryptionAlgorithm(AbstractKeyPair myKeyPair, IASymmetricPublicKey distantPublicKey)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidKeySpecException,
			NoSuchProviderException, InvalidAlgorithmParameterException {
		super();
		if (distantPublicKey == null)
			throw new NullPointerException("distantPublicKey");
		if (myKeyPair instanceof HybridASymmetricKeyPair && distantPublicKey instanceof HybridASymmetricPublicKey)
		{
			p2pencryption=new HybridP2PEncryption((HybridASymmetricKeyPair)myKeyPair, (HybridASymmetricPublicKey)distantPublicKey);
		}
		else if (myKeyPair instanceof ASymmetricKeyPair && distantPublicKey instanceof ASymmetricPublicKey)
			p2pencryption=new P2PEncryption((ASymmetricKeyPair)myKeyPair, (ASymmetricPublicKey)distantPublicKey);
		else
			throw new IllegalArgumentException();
	}
	public P2PASymmetricEncryptionAlgorithm(ASymmetricAuthenticatedSignatureType nonPQCSignatureType,
											ASymmetricAuthenticatedSignatureType PQCSignatureType,
											HybridASymmetricKeyPair myKeyPair, HybridASymmetricPublicKey distantPublicKey)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidKeySpecException,
			NoSuchProviderException, InvalidAlgorithmParameterException {
		super();
		if (distantPublicKey == null)
			throw new NullPointerException("distantPublicKey");
		p2pencryption=new HybridP2PEncryption(nonPQCSignatureType, PQCSignatureType, myKeyPair, distantPublicKey);
	}

	public P2PASymmetricEncryptionAlgorithm(ASymmetricAuthenticatedSignatureType signatureType, ASymmetricKeyPair myKeyPair,
						 ASymmetricPublicKey distantPublicKey) throws NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidKeyException, InvalidKeySpecException, NoSuchProviderException, InvalidAlgorithmParameterException {
		super();
		p2pencryption=new P2PEncryption(signatureType, myKeyPair, distantPublicKey);
	}

	@Override
	public void decode(InputStream is, byte[] associatedData, int offAD, int lenAD, OutputStream os, int length, byte[] externalCounter)
			throws InvalidKeyException, InvalidAlgorithmParameterException, IOException, IllegalBlockSizeException,
			BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IllegalStateException, ShortBufferException
	{
		p2pencryption.decode(is, associatedData, offAD, lenAD, os, lenAD, externalCounter );
	}
	@Override
	public void encode(byte[] bytes, int off, int len, byte[] associatedData, int offAD, int lenAD, OutputStream os, byte[] externalCounter) throws InvalidKeyException,
			IOException, InvalidAlgorithmParameterException, IllegalStateException,
			IllegalBlockSizeException, BadPaddingException,
			NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
		p2pencryption.encode(bytes, off, len, associatedData, offAD, lenAD, os, externalCounter);
	}
	@Override
	public void encode(InputStream is, byte[] associatedData, int offAD, int lenAD, OutputStream os, int length, byte[] externalCounter) throws InvalidKeyException, IOException,
			InvalidAlgorithmParameterException, IllegalStateException, IllegalBlockSizeException,
			BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException,
			NoSuchProviderException, ShortBufferException {
		p2pencryption.encode(is, associatedData, offAD, lenAD, os, lenAD, externalCounter);
	}

	@Override
	public OutputStream getCipherOutputStream(OutputStream os, byte[] externalCounter) throws InvalidKeyException,
			NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidAlgorithmParameterException, IOException, InvalidKeySpecException, NoSuchProviderException {
		return p2pencryption.getCipherOutputStream(os, externalCounter);
	}

	@Override
	public byte[] decode(byte[] bytes) throws InvalidKeyException, InvalidAlgorithmParameterException, IOException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IllegalStateException, ShortBufferException {
		return p2pencryption.decode(bytes);
	}

	@Override
	public byte[] decode(byte[] bytes, byte[] associatedData, byte[] externalCounter) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IOException, IllegalStateException, ShortBufferException {
		return p2pencryption.decode(bytes, associatedData, externalCounter);
	}

	@Override
	public byte[] decode(byte[] bytes, byte[] associatedData) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IOException, IllegalStateException, ShortBufferException {
		return p2pencryption.decode(bytes, associatedData);
	}

	@Override
	public byte[] decode(byte[] bytes, int off, int len) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IOException, IllegalStateException, ShortBufferException {
		return p2pencryption.decode(bytes, off, len);
	}

	@Override
	public byte[] decode(byte[] bytes, int off, int len, byte[] associatedData, int offAD, int lenAD) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IllegalStateException, ShortBufferException, IOException {
		return p2pencryption.decode(bytes, off, len, associatedData, offAD, lenAD);
	}

	@Override
	public byte[] decode(byte[] bytes, int off, int len, byte[] associatedData, int offAD, int lenAD, byte[] externalCounter) throws InvalidKeyException, InvalidAlgorithmParameterException, IOException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IllegalStateException, ShortBufferException {
		return p2pencryption.decode(bytes, off, len, associatedData, offAD, lenAD, externalCounter);
	}

	@Override
	public byte[] decode(InputStream is, byte[] associatedData) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IOException, IllegalStateException, ShortBufferException {
		return p2pencryption.decode(is, associatedData);
	}

	@Override
	public byte[] decode(InputStream is) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IOException, IllegalStateException, ShortBufferException {
		return p2pencryption.decode(is);
	}

	@Override
	public byte[] decode(InputStream is, byte[] associatedData, int offAD, int lenAD) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IllegalStateException, ShortBufferException, IOException {
		return p2pencryption.decode(is, associatedData, offAD, lenAD);
	}

	@Override
	public byte[] decode(InputStream is, byte[] associatedData, int offAD, int lenAD, byte[] externalCounter) throws InvalidKeyException, InvalidAlgorithmParameterException, IOException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IllegalStateException, ShortBufferException {
		return p2pencryption.decode(is, associatedData, offAD, lenAD, externalCounter);
	}

	@Override
	public void decode(InputStream is, byte[] associatedData, OutputStream os) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IOException, IllegalStateException, ShortBufferException {
		p2pencryption.decode(is, associatedData, os);
	}

	@Override
	public void decode(InputStream is, OutputStream os, byte[] externalCounter) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IOException, IllegalStateException, ShortBufferException {
		p2pencryption.decode(is, os, externalCounter);
	}

	@Override
	public void decode(InputStream is, OutputStream os) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IOException, IllegalStateException, ShortBufferException {
		p2pencryption.decode(is, os);
	}

	@Override
	public void decode(InputStream is, byte[] associatedData, int offAD, int lenAD, OutputStream os) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IOException, IllegalStateException, ShortBufferException {
		p2pencryption.decode(is, associatedData, offAD, lenAD, os);
	}

	@Override
	public void decode(InputStream is, byte[] associatedData, int offAD, int lenAD, OutputStream os, byte[] externalCounter) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IOException, IllegalStateException, ShortBufferException {
		p2pencryption.decode(is, associatedData, offAD, lenAD, os, externalCounter);
	}

	@Override
	public void decode(InputStream is, OutputStream os, int length) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IOException, IllegalStateException, ShortBufferException {
		p2pencryption.decode(is, os, length);
	}

	@Override
	public void decode(InputStream is, OutputStream os, int length, byte[] externalCounter) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IOException, IllegalStateException, ShortBufferException {
		p2pencryption.decode(is, os, length, externalCounter);
	}

	@Override
	public void decode(InputStream is, byte[] associatedData, OutputStream os, int length) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IOException, IllegalStateException, ShortBufferException {
		p2pencryption.decode(is, associatedData, os, length);
	}

	@Override
	public void decode(InputStream is, byte[] associatedData, int offAD, int lenAD, OutputStream os, int length) throws InvalidKeyException, InvalidAlgorithmParameterException, IOException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IllegalStateException, ShortBufferException {
		p2pencryption.decode(is, associatedData, offAD, lenAD, os, length);
	}

	@Override
	public InputStream getCipherInputStream(InputStream is) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException, InvalidKeySpecException, NoSuchProviderException {
		return p2pencryption.getCipherInputStream(is);
	}

	@Override
	public byte[] encode(byte[] bytes) throws InvalidKeyException, IOException, InvalidAlgorithmParameterException, BadPaddingException, IllegalStateException, IllegalBlockSizeException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
		return p2pencryption.encode(bytes);
	}

	@Override
	public byte[] encode(byte[] bytes, byte[] associatedData) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalStateException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IOException {
		return p2pencryption.encode(bytes, associatedData);
	}

	@Override
	public byte[] encode(byte[] bytes, byte[] associatedData, byte[] externalCounter) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalStateException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IOException {
		return p2pencryption.encode(bytes, associatedData, externalCounter);
	}

	@Override
	public byte[] encode(byte[] bytes, int off, int len) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalStateException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IOException {
		return p2pencryption.encode(bytes, off, len);
	}

	@Override
	public byte[] encode(byte[] bytes, int off, int len, byte[] associatedData, int offAD, int lenAD) throws InvalidKeyException, IOException, InvalidAlgorithmParameterException, IllegalStateException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
		return p2pencryption.encode(bytes, off, len, associatedData, offAD, lenAD);
	}

	@Override
	public byte[] encode(byte[] bytes, int off, int len, byte[] associatedData, int offAD, int lenAD, byte[] externalCounter) throws InvalidKeyException, IOException, InvalidAlgorithmParameterException, IllegalStateException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
		return p2pencryption.encode(bytes, off, len, associatedData, offAD, lenAD, externalCounter);
	}

	@Override
	public void encode(byte[] bytes, int off, int len, OutputStream os) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalStateException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IOException {
		p2pencryption.encode(bytes, off, len, os);
	}

	@Override
	public void encode(byte[] bytes, int off, int len, byte[] associatedData, int offAD, int lenAD, OutputStream os) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalStateException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IOException {
		p2pencryption.encode(bytes, off, len, associatedData, offAD, lenAD, os);
	}

	@Override
	public void encode(InputStream is, OutputStream os) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalStateException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IOException, ShortBufferException {
		p2pencryption.encode(is, os);
	}

	@Override
	public void encode(InputStream is, byte[] associatedData, OutputStream os) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalStateException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IOException, ShortBufferException {
		p2pencryption.encode(is, associatedData, os);
	}

	@Override
	public void encode(InputStream is, byte[] associatedData, int offAD, int lenAD, OutputStream os) throws InvalidKeyException, IOException, InvalidAlgorithmParameterException, IllegalStateException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, ShortBufferException {
		p2pencryption.encode(is, associatedData, offAD, lenAD, os);
	}

	@Override
	public void encode(InputStream is, OutputStream os, int length) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalStateException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IOException, ShortBufferException {
		p2pencryption.encode(is, os, length);
	}

	@Override
	public void encode(InputStream is, byte[] associatedData, OutputStream os, int length) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalStateException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IOException, ShortBufferException {
		p2pencryption.encode(is, associatedData, os, length);
	}

	@Override
	public void encode(InputStream is, byte[] associatedData, int offAD, int lenAD, OutputStream os, int length) throws InvalidKeyException, IOException, InvalidAlgorithmParameterException, IllegalStateException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, ShortBufferException {
		p2pencryption.encode(is, associatedData, offAD, lenAD, os, length);
	}

	@Override
	public int getMaxBlockSizeForDecoding() {
		return p2pencryption.getMaxBlockSizeForDecoding();
	}

	@Override
	public void initCipherForDecrypt(AbstractCipher cipher, byte[] iv, byte[] externalCounter) throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
		p2pencryption.initCipherForDecrypt(cipher, iv, externalCounter);
	}

	@Override
	protected AbstractCipher getCipherInstance() throws NoSuchAlgorithmException, NoSuchPaddingException, NoSuchProviderException {
		return p2pencryption.getCipherInstance();
	}

	@Override
	public int getMaxBlockSizeForEncoding() {
		return p2pencryption.getMaxBlockSizeForEncoding();
	}

	@Override
	public int getIVSizeBytesWithExternalCounter() {
		return p2pencryption.getIVSizeBytesWithExternalCounter();
	}

	@Override
	protected boolean includeIV() {
		return p2pencryption.includeIV();
	}

	@Override
	public void initCipherForEncrypt(AbstractCipher cipher, byte[] externalCounter) throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
		p2pencryption.initCipherForEncrypt(cipher, externalCounter);
	}

	@Override
	public void initCipherForEncryptAndNotChangeIV(AbstractCipher cipher) throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
		p2pencryption.initCipherForEncryptAndNotChangeIV(cipher);
	}

	@Override
	public boolean isPostQuantumEncryption() {
		return p2pencryption.isPostQuantumEncryption();
	}

	@Override
	public int getOutputSizeForDecryption(int inputLen) throws InvalidKeyException, InvalidAlgorithmParameterException,
			NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
		return p2pencryption.getOutputSizeForDecryption(inputLen);
	}

	@Override
	public InputStream getCipherInputStream(InputStream is, byte[] externalCounter)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, IOException, InvalidKeySpecException, NoSuchProviderException {
		return p2pencryption.getCipherInputStream(is, externalCounter);
	}

	@Override
	public void initCipherForDecrypt(AbstractCipher cipher, byte[] iv) throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
		p2pencryption.initCipherForDecrypt(cipher, iv);
	}

	@Override
	public byte getBlockModeCounterBytes() {
		return p2pencryption.getBlockModeCounterBytes();
	}

	@Override
	public boolean useExternalCounter() {
		return p2pencryption.useExternalCounter();
	}

	@Override
	public void initBufferAllocatorArgs() {
		p2pencryption.initBufferAllocatorArgs();
	}

	@Override
	public int getOutputSizeForEncryption(int inputLen) throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
		return p2pencryption.getOutputSizeForEncryption(inputLen);
	}

	@Override
	public void initCipherForEncrypt(AbstractCipher cipher) throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
		p2pencryption.initCipherForEncrypt(cipher);
	}

	private static class HybridP2PEncryption extends AbstractEncryptionIOAlgorithm
	{
		private final P2PEncryption nonPQCEncryption, PQCEncryption;
		private final HybridASymmetricKeyPair myKeyPair;
		private final HybridASymmetricPublicKey distantPublicKey;

		public HybridP2PEncryption(HybridASymmetricKeyPair myKeyPair,
							 HybridASymmetricPublicKey distantPublicKey) throws NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, InvalidKeySpecException {
			super();
			nonPQCEncryption=new P2PEncryption(myKeyPair.getNonPQCASymmetricKeyPair(), distantPublicKey.getNonPQCPublicKey());
			PQCEncryption=new P2PEncryption(myKeyPair.getPQCASymmetricKeyPair(), distantPublicKey.getPQCPublicKey());
			if (nonPQCEncryption.includeIV()!=PQCEncryption.includeIV())
				throw new IllegalArgumentException();
			this.myKeyPair=myKeyPair;
			this.distantPublicKey=distantPublicKey;
		}

		public HybridP2PEncryption(ASymmetricAuthenticatedSignatureType nonPQCSignatureType,
								   ASymmetricAuthenticatedSignatureType PQCSignatureType,
								   HybridASymmetricKeyPair myKeyPair,
								   HybridASymmetricPublicKey distantPublicKey) throws NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, InvalidKeySpecException {
			super();
			nonPQCEncryption=new P2PEncryption(nonPQCSignatureType, myKeyPair.getNonPQCASymmetricKeyPair(), distantPublicKey.getNonPQCPublicKey());
			PQCEncryption=new P2PEncryption(PQCSignatureType, myKeyPair.getPQCASymmetricKeyPair(), distantPublicKey.getPQCPublicKey());
			if (nonPQCEncryption.includeIV()!=PQCEncryption.includeIV())
				throw new IllegalArgumentException();
			this.myKeyPair=myKeyPair;
			this.distantPublicKey=distantPublicKey;
		}


		@Override
		public int getMaxBlockSizeForDecoding() {
			return Math.min(nonPQCEncryption.getMaxBlockSizeForDecoding(), PQCEncryption.getMaxBlockSizeForDecoding());
		}

		@Override
		public void initCipherForDecrypt(AbstractCipher cipher, byte[] iv, byte[] externalCounter)  {
			throw new IllegalAccessError();
		}

		@Override
		protected AbstractCipher getCipherInstance()  {
			throw new IllegalAccessError();
		}

		@Override
		public int getMaxBlockSizeForEncoding() {
			return Math.min(nonPQCEncryption.getMaxBlockSizeForEncoding(), PQCEncryption.getMaxBlockSizeForEncoding());
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
		public void initCipherForEncryptAndNotChangeIV(AbstractCipher cipher) {
			throw new IllegalAccessError();
		}

		@Override
		public boolean isPostQuantumEncryption() {
			return true;
		}

		@Override
		public int getOutputSizeForDecryption(int inputLen) throws InvalidKeyException, InvalidAlgorithmParameterException,
				NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
			return PQCEncryption.getOutputSizeForDecryption(nonPQCEncryption.getOutputSizeForDecryption(inputLen));
		}

		@Override
		public int getOutputSizeForEncryption(int inputLen) throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
			return nonPQCEncryption.getOutputSizeForEncryption(PQCEncryption.getOutputSizeForEncryption(inputLen));
		}

		private int privDecode(InputStream is, byte[] associatedData, int offAD, int lenAD, OutputStream os, int length, byte[] externalCounter)
				throws InvalidKeyException, InvalidAlgorithmParameterException, IOException, IllegalBlockSizeException,
				BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IllegalStateException, ShortBufferException
		{
			int totalBytes=0;
			while(length>0) {
				ByteArrayOutputStream baos=new ByteArrayOutputStream();

				int l=Math.min(buffer.length, length);
				int nb=is.read(buffer);
				if (nb<0) {
					if (totalBytes==0)
						--totalBytes;
					break;
				}
				nonPQCEncryption.decode(is, associatedData, offAD, lenAD, baos, l, externalCounter);
				byte []b=baos.toByteArray();
				os.write(PQCEncryption.decode(b, 0, b.length, associatedData, offAD, lenAD, externalCounter));
				length-=l;
				totalBytes+=l;
			}

			return totalBytes;
		}

		@Override
		public void decode(InputStream is, byte[] associatedData, int offAD, int lenAD, OutputStream os, int length, byte[] externalCounter)
				throws InvalidKeyException, InvalidAlgorithmParameterException, IOException, IllegalBlockSizeException,
				BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IllegalStateException, ShortBufferException
		{
			privDecode(is, associatedData, offAD, lenAD, os, lenAD, externalCounter);
		}
		@Override
		public void encode(byte[] bytes, int off, int len, byte[] associatedData, int offAD, int lenAD, OutputStream os, byte[] externalCounter) throws InvalidKeyException,
				IOException, InvalidAlgorithmParameterException, IllegalStateException,
				IllegalBlockSizeException, BadPaddingException,
				NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
			ByteArrayOutputStream baos=new ByteArrayOutputStream();
			PQCEncryption.encode(bytes, off, len, associatedData, offAD, lenAD, baos, externalCounter);
			byte[] b=baos.toByteArray();
			nonPQCEncryption.encode(b, 0, b.length, associatedData, offAD, lenAD, os, externalCounter);
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
				PQCEncryption.encode(buffer, 0, nb, associatedData, offAD, lenAD, baos, externalCounter);
				byte[] b=baos.toByteArray();
				nonPQCEncryption.encode(b, 0, b.length, associatedData, offAD, lenAD, os, externalCounter);

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

		@Override
		public InputStream getCipherInputStream(final InputStream is, final byte[] externalCounter)
		{
			return new InputStream() {
				private final byte[] one=new byte[1];
				@Override
				public int read() throws IOException {
					if (read(one, 0, 1)==1)
						return one[0];
					else
						return -1;
				}

				@Override
				public int read(byte[] b, int off, int len) throws IOException {
					try {
						return privDecode(is, null, 0, 0, new ArrayOutputStream(b, off, len), len, externalCounter);
					} catch (InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException | NoSuchAlgorithmException | InvalidKeySpecException | NoSuchProviderException | ShortBufferException e) {
						throw new IOException();
					}
				}
			};
		}


	}
	private static class ArrayOutputStream extends OutputStream
	{
		private final byte[] target;
		private int off;
		private int len;

		public ArrayOutputStream(byte[] target, int off, int len) {
			this.target = target;
			this.off = off;
			this.len = len;
		}

		@Override
		public void write(int b) throws IOException {
			if (len<=0)
				throw new IOException();
			target[off++]=(byte)b;
			--len;
		}

		@Override
		public void write(byte[] b, int off, int len) throws IOException {
			int l=Math.min(len, this.len);
			System.arraycopy(b, off, target, this.off, l);
			this.len-=l;
			this.off+=l;
			if (len>l)
				throw new IOException();
		}
	}

	public IASymmetricPublicKey getDistantPublicKey() {
		if (this.p2pencryption instanceof P2PEncryption)
			return ((P2PEncryption)p2pencryption).getDistantPublicKey();
		else
			return ((HybridP2PEncryption)p2pencryption).distantPublicKey;
	}
	public AbstractKeyPair getMyKeyPair() {
		if (this.p2pencryption instanceof P2PEncryption)
			return ((P2PEncryption)p2pencryption).getMyKeyPair();
		else
			return ((HybridP2PEncryption)p2pencryption).myKeyPair;
	}

	private static class P2PEncryption extends AbstractEncryptionIOAlgorithm {
		private final ASymmetricKeyPair myKeyPair;

		private final ASymmetricPublicKey distantPublicKey;

		private final ASymmetricEncryptionType type;

		private final ASymmetricAuthenticatedSignatureType signatureType;

		private final int maxBlockSizeForEncoding, maxBlockSizeForDecoding;

		@Override
		public boolean isPostQuantumEncryption() {
			return myKeyPair.isPostQuantumKey() && distantPublicKey.isPostQuantumKey();
		}

		public P2PEncryption(ASymmetricKeyPair myKeyPair, ASymmetricPublicKey distantPublicKey)
				throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidKeySpecException,
				NoSuchProviderException, InvalidAlgorithmParameterException {
			this(myKeyPair.getEncryptionAlgorithmType().getDefaultSignatureAlgorithm(), myKeyPair, distantPublicKey);
		}

		public P2PEncryption(ASymmetricAuthenticatedSignatureType signatureType, ASymmetricKeyPair myKeyPair,
												ASymmetricPublicKey distantPublicKey) throws NoSuchAlgorithmException, NoSuchPaddingException,
				InvalidKeyException, InvalidKeySpecException, NoSuchProviderException, InvalidAlgorithmParameterException {
			super(myKeyPair.getEncryptionAlgorithmType().getCipherInstance(), 0);
			if (signatureType == null)
				throw new NullPointerException("signatureType");
			if (distantPublicKey == null)
				throw new NullPointerException("distantPublicKey");

			this.type = myKeyPair.getEncryptionAlgorithmType();
			this.myKeyPair = myKeyPair;
			this.distantPublicKey = distantPublicKey;
			this.signatureType = signatureType;
			// initCipherForEncrypt(this.cipher);
			this.maxBlockSizeForEncoding = myKeyPair.getMaxBlockSize();
			initCipherForEncrypt(this.cipher);
			this.maxBlockSizeForDecoding = cipher.getOutputSize(this.maxBlockSizeForEncoding);
			initBufferAllocatorArgs();
		}

		@Override
		protected AbstractCipher getCipherInstance() throws NoSuchAlgorithmException, NoSuchPaddingException, NoSuchProviderException {
			return type.getCipherInstance();
		}

		public ASymmetricPublicKey getDistantPublicKey() {
			return this.distantPublicKey;
		}

		@Override
		public int getMaxBlockSizeForDecoding() {
			return maxBlockSizeForDecoding;
		}

		@Override
		public int getMaxBlockSizeForEncoding() {
			return maxBlockSizeForEncoding;
		}

		public ASymmetricKeyPair getMyKeyPair() {
			return this.myKeyPair;
		}

		public ASymmetricAuthenticatedSignatureType getSignatureType() {
			return signatureType;
		}

		@Override
		protected boolean includeIV() {
			return false;
		}

		@Override
		public void initCipherForDecrypt(AbstractCipher _cipher, byte[] iv, byte[] externalCounter)
				throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
			_cipher.init(Cipher.DECRYPT_MODE, myKeyPair.getASymmetricPrivateKey());
		}

		@Override
		public void initCipherForEncrypt(AbstractCipher _cipher, byte[] externalCounter)
				throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
			initCipherForEncryptAndNotChangeIV(_cipher);
		}

		@Override
		public void initCipherForEncryptAndNotChangeIV(AbstractCipher _cipher)
				throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
			_cipher.init(Cipher.ENCRYPT_MODE, distantPublicKey);

		}


		@Override
		public int getIVSizeBytesWithExternalCounter() {
			return 0;
		}
	}
}

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

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

/**
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 4.16.0
 */
public class EncryptionSignatureHashDecoder {

	private RandomInputStream inputStream=null;
	private SymmetricEncryptionAlgorithm cipher=null;
	private byte[] associatedData=null;
	private int offAD=0;
	private int lenAD=0;
	private SymmetricAuthenticatedSignatureCheckerAlgorithm symmetricChecker=null;
	private ASymmetricAuthenticatedSignatureCheckerAlgorithm asymmetricChecker=null;
	private AbstractMessageDigest digest=null;
	Long minimumInputSize=null;

	public EncryptionSignatureHashDecoder() {
	}
	public EncryptionSignatureHashDecoder withRandomInputStream(RandomInputStream inputStream) throws IOException {
		if (inputStream==null)
			throw new NullPointerException();
		if (inputStream.length()-inputStream.currentPosition()==0)
			throw new IllegalArgumentException();
		this.inputStream=inputStream;
		return this;
	}

	public EncryptionSignatureHashDecoder withSymmetricSecretKeyForEncryption(AbstractSecureRandom random, SymmetricSecretKey symmetricSecretKeyForEncryption) throws IOException {
		return withCipher(new SymmetricEncryptionAlgorithm(random, symmetricSecretKeyForEncryption));
	}
	public EncryptionSignatureHashDecoder withSymmetricSecretKeyForEncryptionAndAssociatedData(AbstractSecureRandom random, SymmetricSecretKey symmetricSecretKeyForEncryption, byte[] associatedData) throws IOException {
		return withSymmetricSecretKeyForEncryptionAndAssociatedData(random, symmetricSecretKeyForEncryption, associatedData, 0, associatedData.length);
	}
	public EncryptionSignatureHashDecoder withSymmetricSecretKeyForEncryptionAndAssociatedData(AbstractSecureRandom random, SymmetricSecretKey symmetricSecretKeyForEncryption, byte[] associatedData, int offAD, int lenAD) throws IOException {
		return withCipherAndAssociatedData(new SymmetricEncryptionAlgorithm(random, symmetricSecretKeyForEncryption), associatedData, offAD, lenAD);
	}

	public EncryptionSignatureHashDecoder withCipher(SymmetricEncryptionAlgorithm cipher) throws IOException {
		if (cipher==null)
			throw new NullPointerException();
		if (this.symmetricChecker!=null && cipher.getType().isAuthenticatedAlgorithm())
			throw new IOException("Symmetric encryption use authentication and a symmetric authenticated signer is already used. No more symmetric authentication is needed. However ASymmetric authentication is possible.");
		this.cipher=cipher;
		this.associatedData=null;
		return this;

	}

	public EncryptionSignatureHashDecoder withCipherAndAssociatedData(SymmetricEncryptionAlgorithm cipher, byte[] associatedData, int offAD, int lenAD) throws IOException {
		if (cipher==null)
			throw new NullPointerException();
		if (associatedData==null)
			throw new NullPointerException();
		if (!cipher.getType().supportAssociatedData())
			throw new IllegalArgumentException("Cipher does not support associated data !");
		EncryptionSignatureHashEncoder.checkLimits(associatedData, offAD, lenAD);
		if (this.symmetricChecker!=null && cipher.getType().isAuthenticatedAlgorithm())
			throw new IOException("Symmetric encryption use authentication and a symmetric authenticated signer is already used. No more symmetric authentication is needed. However ASymmetric authentication is possible.");
		this.cipher=cipher;
		this.associatedData=associatedData;
		this.offAD=offAD;
		this.lenAD=lenAD;
		return this;
	}
	public EncryptionSignatureHashDecoder withMessageDigest(AbstractMessageDigest messageDigest)
	{
		if (digest==null)
			throw new NullPointerException();
		this.digest=messageDigest;
		minimumInputSize=null;
		return this;
	}
	public EncryptionSignatureHashDecoder withMessageDigestType(MessageDigestType messageDigestType) throws IOException {
		if (messageDigestType==null)
			throw new NullPointerException();
		try {
			this.digest=messageDigestType.getMessageDigestInstance();
			minimumInputSize=null;
		} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
			throw new IOException(e);
		}
		return this;
	}
	public EncryptionSignatureHashDecoder withSymmetricChecker(SymmetricAuthenticatedSignatureCheckerAlgorithm symmetricChecker) throws IOException {
		if (symmetricChecker==null)
			throw new NullPointerException();
		if (this.cipher!=null && this.cipher.getType().isAuthenticatedAlgorithm())
			throw new IOException("Symmetric encryption use authentication. No more symmetric authentication is needed. However ASymmetric authentication is possible.");
		this.symmetricChecker=symmetricChecker;
		minimumInputSize=null;
		return this;
	}
	public EncryptionSignatureHashDecoder withSymmetricSecretKeyForSignature(SymmetricSecretKey secretKeyForSignature) throws IOException {
		if (secretKeyForSignature==null)
			throw new NullPointerException();
		if (!secretKeyForSignature.useAuthenticatedSignatureAlgorithm())
			throw new IllegalArgumentException();
		try {
			return withSymmetricChecker(new SymmetricAuthenticatedSignatureCheckerAlgorithm(secretKeyForSignature));
		} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
			throw new IOException(e);
		}
	}

	public EncryptionSignatureHashDecoder withASymmetricChecker(ASymmetricAuthenticatedSignatureCheckerAlgorithm asymmetricChecker)
	{
		if (asymmetricChecker==null)
			throw new NullPointerException();
		this.asymmetricChecker=asymmetricChecker;
		minimumInputSize=null;
		return this;
	}

	public EncryptionSignatureHashDecoder withASymmetricPublicKeyForSignature(IASymmetricPublicKey publicKeyForSignature) throws IOException {
		if (publicKeyForSignature==null)
			throw new NullPointerException();
		if (!publicKeyForSignature.useAuthenticatedSignatureAlgorithm())
			throw new IllegalArgumentException();
		try {
			this.asymmetricChecker=new ASymmetricAuthenticatedSignatureCheckerAlgorithm(publicKeyForSignature);
			minimumInputSize=null;
		} catch (NoSuchProviderException | NoSuchAlgorithmException e) {
			throw new IOException(e);
		}
		return this;
	}

	private long getMinimumInputSize()
	{
		if (minimumInputSize==null)
			minimumInputSize=EncryptionSignatureHashEncoder.getMinimumInputLengthAfterDecoding(symmetricChecker, asymmetricChecker, digest);
		return minimumInputSize;
	}

	public void decodeAndCheckHashAndSignaturesIfNecessary(RandomOutputStream outputStream) throws IOException {
		if (outputStream==null)
			throw new NullPointerException();
		EncryptionSignatureHashEncoder.decryptAndCheckHashAndSignaturesImpl(inputStream, outputStream, cipher, associatedData, offAD, lenAD, symmetricChecker,asymmetricChecker, digest, getMinimumInputSize());
	}
	public Integrity checkHashAndSignature() throws IOException {
		return EncryptionSignatureHashEncoder.checkHashAndSignatureImpl(inputStream, symmetricChecker,asymmetricChecker, digest);
	}
	public Integrity checkHashAndPublicSignature() throws IOException {
		return EncryptionSignatureHashEncoder.checkHashAndPublicSignatureImpl(inputStream,asymmetricChecker, digest);
	}
	public SubStreamHashResult computePartialHash(SubStreamParameters subStreamParameters) throws IOException {

		try {
			if (cipher == null) {
				return new SubStreamHashResult(subStreamParameters.generateHash(inputStream), null);
			} else {
				return cipher.getIVAndPartialHashedSubStreamFromEncryptedStream(inputStream, subStreamParameters);
			}
		} catch (NoSuchProviderException | NoSuchAlgorithmException e) {
			throw new IOException(e);
		}
	}
	public long getMaximumOutputLength() throws IOException {
		return EncryptionSignatureHashEncoder.getMaximumOutputLengthAfterDecoding(inputStream.length(), cipher, getMinimumInputSize());
	}

	public long getMaximumOutputLength(long inputStreamLength) throws IOException {
		return EncryptionSignatureHashEncoder.getMaximumOutputLengthAfterDecoding(inputStreamLength, cipher, getMinimumInputSize());
	}
}

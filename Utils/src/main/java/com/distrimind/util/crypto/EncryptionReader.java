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
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;

/**
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 4.16.0
 */
public class EncryptionReader {

	private final RandomInputStream inputStream;
	private final RandomOutputStream outputStream;
	private SymmetricEncryptionAlgorithm cipher=null;
	private byte[] associatedData=null;
	private int offAD=0;
	private int lenAD=0;
	private SymmetricAuthenticatedSignatureCheckerAlgorithm symmetricChecker=null;
	private ASymmetricAuthenticatedSignatureCheckerAlgorithm asymmetricChecker=null;
	private AbstractMessageDigest digest=null;

	public EncryptionReader(RandomInputStream inputStream, RandomOutputStream outputStream) throws IOException {
		if (inputStream==null)
			throw new NullPointerException();
		if (inputStream.length()-inputStream.currentPosition()==0)
			throw new IllegalArgumentException();
		if (outputStream==null)
			throw new NullPointerException();

		this.inputStream = inputStream;
		this.outputStream = outputStream;
	}

	public EncryptionReader withCipher(SymmetricEncryptionAlgorithm cipher)
	{
		if (cipher==null)
			throw new NullPointerException();
		this.cipher=cipher;
		return this;
	}
	public EncryptionReader withCipherAndAssociatedData(SymmetricEncryptionAlgorithm cipher, byte[] associatedData, int offAD, int lenAD)
	{
		if (cipher==null)
			throw new NullPointerException();
		if (associatedData==null)
			throw new NullPointerException();
		EncryptionWriter.checkLimits(associatedData, offAD, lenAD);
		this.cipher=cipher;
		this.associatedData=associatedData;
		this.offAD=offAD;
		this.lenAD=lenAD;
		return this;
	}
	public EncryptionReader withMessageDigest(AbstractMessageDigest messageDigest)
	{
		if (digest==null)
			throw new NullPointerException();
		this.digest=messageDigest;
		return this;
	}
	public EncryptionReader withMessageDigestType(MessageDigestType messageDigestType) throws NoSuchProviderException, NoSuchAlgorithmException {
		if (messageDigestType==null)
			throw new NullPointerException();
		this.digest=messageDigestType.getMessageDigestInstance();
		return this;
	}
	public EncryptionReader withSymmetricChecker(SymmetricAuthenticatedSignatureCheckerAlgorithm symmetricChecker)
	{
		if (symmetricChecker==null)
			throw new NullPointerException();
		this.symmetricChecker=symmetricChecker;
		return this;
	}
	public EncryptionReader withSymmetricSecretKeyForSignature(SymmetricSecretKey secretKeyForSignature) throws NoSuchProviderException, NoSuchAlgorithmException {
		if (secretKeyForSignature==null)
			throw new NullPointerException();
		if (!secretKeyForSignature.useAuthenticatedSignatureAlgorithm())
			throw new IllegalArgumentException();
		this.symmetricChecker=new SymmetricAuthenticatedSignatureCheckerAlgorithm(secretKeyForSignature);
		return this;
	}

	public EncryptionReader withASymmetricChecker(ASymmetricAuthenticatedSignatureCheckerAlgorithm asymmetricChecker)
	{
		if (asymmetricChecker==null)
			throw new NullPointerException();
		this.asymmetricChecker=asymmetricChecker;
		return this;
	}

	public EncryptionReader withASymmetricPublicKeyForSignature(IASymmetricPublicKey publicKeyForSignature) throws NoSuchProviderException, NoSuchAlgorithmException {
		if (publicKeyForSignature==null)
			throw new NullPointerException();
		if (!publicKeyForSignature.useAuthenticatedSignatureAlgorithm())
			throw new IllegalArgumentException();
		this.asymmetricChecker=new ASymmetricAuthenticatedSignatureCheckerAlgorithm(publicKeyForSignature);
		return this;
	}

	public void decryptAndCheckHashAndSignatures() throws IOException {
		EncryptionWriter.decryptAndCheckHashAndSignaturesImpl(inputStream, outputStream, cipher, associatedData, offAD, lenAD, symmetricChecker,asymmetricChecker, digest);
	}
	public Integrity checkHashAndSignature() throws IOException {
		return EncryptionWriter.checkHashAndSignatureImpl(inputStream, symmetricChecker,asymmetricChecker, digest);
	}
	public Integrity checkHashAndPublicSignature() throws IOException {
		return EncryptionWriter.checkHashAndPublicSignatureImpl(inputStream,asymmetricChecker, digest);
	}
	public SubStreamHashResult computePartialHash(SubStreamParameters subStreamParameters) throws IOException {

		try {
			if (cipher == null) {
				return new SubStreamHashResult(subStreamParameters.generateHash(inputStream), null);
			} else {
				return cipher.getIVAndPartialHashedSubStreamFromEncryptedStream(inputStream, associatedData, offAD, lenAD, subStreamParameters);
			}
		} catch (NoSuchProviderException | NoSuchAlgorithmException | InvalidAlgorithmParameterException | InvalidKeySpecException | InvalidKeyException e) {
			throw new IOException(e);
		}
	}
}

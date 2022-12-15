package com.distrimind.util.crypto;
/*
Copyright or © or Corp. Jason Mahdjoub (01/04/2013)

jason.mahdjoub@distri-mind.fr

This software (Object Oriented Database (OOD)) is a computer program 
whose purpose is to manage a local database with the object paradigm 
and the java language 

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

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

/**
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 5.24.0
 */
class KeyAgreementWithSimpleKeyWrapping extends AbstractKeyAgreementWithKeyWrapping<ASymmetricPublicKey, ASymmetricPrivateKey, ASymmetricKeyPair> implements ISimpleKeyAgreement {
	static ASymmetricKeyPair generateKeyPair(ASymmetricKeyWrapperType aSymmetricKeyWrapperType, AbstractSecureRandom random) throws NoSuchAlgorithmException, IOException, NoSuchProviderException {
		if (aSymmetricKeyWrapperType.isHybrid())
			throw new IllegalArgumentException();
		return (ASymmetricKeyPair)aSymmetricKeyWrapperType.getKeyPairGenerator(random).generateKeyPair();
	}
	KeyAgreementWithSimpleKeyWrapping(AbstractSecureRandom random, ASymmetricKeyWrapperType aSymmetricKeyWrapperType, ASymmetricAuthenticatedSignatureType aSymmetricAuthenticatedSignatureType, short keySizeBits, SymmetricAuthenticatedSignatureType signatureType) throws NoSuchAlgorithmException, IOException, NoSuchProviderException {
		this(random, aSymmetricKeyWrapperType, generateKeyPair(aSymmetricKeyWrapperType, random), aSymmetricAuthenticatedSignatureType.getKeyPairGenerator(random).generateKeyPair(), keySizeBits, signatureType);
	}
	KeyAgreementWithSimpleKeyWrapping(AbstractSecureRandom random, ASymmetricKeyWrapperType aSymmetricKeyWrapperType, ASymmetricAuthenticatedSignatureType aSymmetricAuthenticatedSignatureType, short keySizeBits, SymmetricEncryptionType encryptionType) throws NoSuchAlgorithmException, IOException, NoSuchProviderException {
		this(random, aSymmetricKeyWrapperType, generateKeyPair(aSymmetricKeyWrapperType, random), aSymmetricAuthenticatedSignatureType.getKeyPairGenerator(random).generateKeyPair(), keySizeBits, encryptionType);
	}

	KeyAgreementWithSimpleKeyWrapping(AbstractSecureRandom random, ASymmetricKeyWrapperType aSymmetricKeyWrapperType, ASymmetricKeyPair keyPairForEncryption, ASymmetricKeyPair keyPairForSignature, short keySizeBits, SymmetricAuthenticatedSignatureType signatureType) throws NoSuchAlgorithmException, NoSuchProviderException {
		super(random, aSymmetricKeyWrapperType, keyPairForEncryption, keyPairForSignature, keySizeBits, signatureType, null);
	}

	KeyAgreementWithSimpleKeyWrapping(AbstractSecureRandom random, ASymmetricKeyWrapperType aSymmetricKeyWrapperType, ASymmetricKeyPair keyPairForEncryption, ASymmetricKeyPair keyPairForSignature, short keySizeBits, SymmetricEncryptionType encryptionType) throws NoSuchAlgorithmException, NoSuchProviderException {
		super(random, aSymmetricKeyWrapperType, keyPairForEncryption, keyPairForSignature, keySizeBits, null, encryptionType);
	}

	@Override
	public SymmetricSecretKey getDerivedSecretKey() {
		return super.getDerivedKey();
	}

}

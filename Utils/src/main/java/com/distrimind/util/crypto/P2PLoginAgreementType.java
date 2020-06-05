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


import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

/**
 * @author Jason Mahdjoub
 * @version 3.1
 * @since MaDKitLanEdition 3.15.0
 */
public enum P2PLoginAgreementType {
	JPAKE(false),
	AGREEMENT_WITH_SYMMETRIC_SIGNATURE(true),
	JPAKE_AND_AGREEMENT_WITH_SYMMETRIC_SIGNATURE(false),
	ASYMMETRIC_SECRET_MESSAGE_EXCHANGER(false),
	ASYMMETRIC_SECRET_MESSAGE_EXCHANGER_AND_AGREEMENT_WITH_SYMMETRIC_SIGNATURE(false);

	private final boolean pqc;


	P2PLoginAgreementType(boolean pqc)
	{
		this.pqc=pqc;
	}

	private MessageDigestType getDefaultMessageDigestType()
	{
		return MessageDigestType.DEFAULT;
	}
	private PasswordHashType getDefaultPasswordHashType()
	{
		return PasswordHashType.PBKDF2WithHMacSHA2_512;
	}

	private ASymmetricPublicKey generateASymmetricPublicKey(AbstractSecureRandom random) throws NoSuchAlgorithmException, NoSuchProviderException, IOException {
		return ASymmetricEncryptionType.DEFAULT.getKeyPairGenerator(random).generateKeyPair().getASymmetricPublicKey();
	}
	public P2PLoginAgreement getAgreementAlgorithm(AbstractSecureRandom random, byte[] participantID, char[] message, SymmetricSecretKey secretKeyForSignature) throws NoSuchAlgorithmException, NoSuchProviderException, IOException {
		return getAgreementAlgorithm(random, participantID, message, secretKeyForSignature, getDefaultMessageDigestType(), getDefaultPasswordHashType(), generateASymmetricPublicKey(random));
	}
	public P2PLoginAgreement getAgreementAlgorithm(AbstractSecureRandom random, byte[] participantID, char[] message, SymmetricSecretKey secretKeyForSignature,MessageDigestType messageDigestType, PasswordHashType passwordHashType,
												   ASymmetricPublicKey myPublicKey) throws NoSuchAlgorithmException,  NoSuchProviderException, IOException{
		return getAgreementAlgorithm(random, participantID, message, null, 0, 0, secretKeyForSignature, messageDigestType, passwordHashType, myPublicKey);
	}
	public P2PLoginAgreement getAgreementAlgorithm(AbstractSecureRandom random, byte[] participantID, char[] message, byte[] salt,
												   int offset_salt, int len_salt, SymmetricSecretKey secretKeyForSignature) throws NoSuchAlgorithmException, NoSuchProviderException, IOException{
		return getAgreementAlgorithm(random, participantID, message, salt, offset_salt, len_salt, secretKeyForSignature, getDefaultMessageDigestType(), getDefaultPasswordHashType(), generateASymmetricPublicKey(random));
	}
	public P2PLoginAgreement getAgreementAlgorithm(AbstractSecureRandom random, byte[] participantID, char[] message, byte[] salt,
												   int offset_salt, int len_salt, SymmetricSecretKey secretKeyForSignature,MessageDigestType messageDigestType, PasswordHashType passwordHashType,
												   ASymmetricPublicKey myPublicKey) throws NoSuchAlgorithmException, NoSuchProviderException, IOException {
		
		switch(this)
		{
		case AGREEMENT_WITH_SYMMETRIC_SIGNATURE:
			return new P2PLoginWithSymmetricSignature(secretKeyForSignature, random);
		case JPAKE:
			return new P2PJPAKESecretMessageExchanger(random, participantID, message, salt, offset_salt, len_salt);
		case JPAKE_AND_AGREEMENT_WITH_SYMMETRIC_SIGNATURE:
			return new P2PJPakeAndLoginAgreement(random, participantID, message, salt, offset_salt, len_salt, secretKeyForSignature);
		case ASYMMETRIC_SECRET_MESSAGE_EXCHANGER:
			return new P2PASymmetricSecretMessageExchangerAgreement(random, messageDigestType, passwordHashType, myPublicKey, salt, offset_salt, len_salt, message);

		case ASYMMETRIC_SECRET_MESSAGE_EXCHANGER_AND_AGREEMENT_WITH_SYMMETRIC_SIGNATURE:
			return new P2PASymmetricSecretMessageExchangerAgreementWithSymmetricSignature(random, message, salt, offset_salt, len_salt, secretKeyForSignature, messageDigestType, passwordHashType, myPublicKey);
		}

		throw new IllegalAccessError();
	}
	public P2PLoginAgreement getAgreementAlgorithm(AbstractSecureRandom random, byte[] participantID, byte[] message, boolean messageIsKey, SymmetricSecretKey secretKeyForSignature) throws NoSuchAlgorithmException, NoSuchProviderException, IOException {
		return getAgreementAlgorithm(random, participantID, message, messageIsKey, secretKeyForSignature,getDefaultMessageDigestType(), getDefaultPasswordHashType(), generateASymmetricPublicKey(random));
	}
	public P2PLoginAgreement getAgreementAlgorithm(AbstractSecureRandom random, byte[] participantID, byte[] message, boolean messageIsKey, SymmetricSecretKey secretKeyForSignature,MessageDigestType messageDigestType, PasswordHashType passwordHashType,
												   ASymmetricPublicKey myPublicKey) throws NoSuchAlgorithmException, NoSuchProviderException, IOException {
		return getAgreementAlgorithm(random, participantID, message, 0, message.length,null, 0, 0, messageIsKey, secretKeyForSignature, messageDigestType, passwordHashType, myPublicKey);
	}
	public P2PLoginAgreement getAgreementAlgorithm(AbstractSecureRandom random, byte[] participantID, byte[] message, int offset, int len, byte[] salt,
												   int offset_salt, int len_salt, boolean messageIsKey, SymmetricSecretKey secretKeyForSignature) throws NoSuchAlgorithmException, NoSuchProviderException, IOException {
		return getAgreementAlgorithm(random, participantID, message, offset, len, salt, offset_salt, len_salt, messageIsKey, secretKeyForSignature,getDefaultMessageDigestType(), getDefaultPasswordHashType(), generateASymmetricPublicKey(random));
	}

	public P2PLoginAgreement getAgreementAlgorithm(AbstractSecureRandom random, byte[] participantID, byte[] message, int offset, int len, byte[] salt,
												   int offset_salt, int len_salt, boolean messageIsKey, SymmetricSecretKey secretKeyForSignature,MessageDigestType messageDigestType, PasswordHashType passwordHashType,
												   ASymmetricPublicKey myPublicKey) throws NoSuchAlgorithmException, NoSuchProviderException, IOException {
		switch(this)
		{
		case AGREEMENT_WITH_SYMMETRIC_SIGNATURE:
			return new P2PLoginWithSymmetricSignature(secretKeyForSignature, random);
		case JPAKE:
			return new P2PJPAKESecretMessageExchanger(random, participantID, message, offset, len, salt, offset_salt, len_salt, messageIsKey);
		case JPAKE_AND_AGREEMENT_WITH_SYMMETRIC_SIGNATURE:
			return new P2PJPakeAndLoginAgreement(random, participantID, message, offset, len, salt, offset_salt, len_salt, messageIsKey, secretKeyForSignature);
		case ASYMMETRIC_SECRET_MESSAGE_EXCHANGER:
			return new P2PASymmetricSecretMessageExchangerAgreement(random, messageDigestType, passwordHashType, myPublicKey, salt, offset_salt, len_salt, message, offset, len, messageIsKey);

		case ASYMMETRIC_SECRET_MESSAGE_EXCHANGER_AND_AGREEMENT_WITH_SYMMETRIC_SIGNATURE:
			return new P2PASymmetricSecretMessageExchangerAgreementWithSymmetricSignature(random, message, offset, len, salt, offset_salt, len_salt, messageIsKey, secretKeyForSignature, messageDigestType, passwordHashType, myPublicKey);
		}
		throw new IllegalAccessError();
	}

	public boolean isPostQuantumAlgorithm(SymmetricSecretKey secretKey)
	{
		return pqc && secretKey!=null && secretKey.isPostQuantumKey();
	}
}

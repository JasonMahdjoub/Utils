package com.distrimind.util.crypto;

import java.io.IOException;
import java.io.Serializable;

import gnu.vm.jgnu.security.NoSuchAlgorithmException;
import gnu.vm.jgnu.security.NoSuchProviderException;
import gnu.vm.jgnu.security.spec.InvalidKeySpecException;

public enum P2PLoginAgreementType {
	JPAKE,
	AGREEMENT_WITH_SIGNATURE,
	JPAKE_AND_AGREEMENT_WITH_SIGNATURE;
	
	
	public P2PLoginAgreement getAgreementAlgorithm(AbstractSecureRandom random, Serializable participantID, char[] message, SymmetricSecretKey secretKeyForSignature) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IOException
	{
		return getAgreementAlgorithm(random, participantID, message, null, 0, 0, secretKeyForSignature);
	}
	public P2PLoginAgreement getAgreementAlgorithm(AbstractSecureRandom random, Serializable participantID, char[] message, byte salt[],
			int offset_salt, int len_salt, SymmetricSecretKey secretKeyForSignature) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IOException
	{
		switch(this)
		{
		case AGREEMENT_WITH_SIGNATURE:
			return new P2PLoginWithSignature(secretKeyForSignature, random);
		case JPAKE:
			return new P2PJPAKESecretMessageExchanger(random, participantID, message, salt, offset_salt, len_salt);
		case JPAKE_AND_AGREEMENT_WITH_SIGNATURE:
			return new P2PJPakeAndLoginAgreement(random, participantID, message, salt, offset_salt, len_salt, secretKeyForSignature);
		}
		throw new IllegalAccessError(); 
	}
	public P2PLoginAgreement getAgreementAlgorithm(AbstractSecureRandom random, Serializable participantID, byte[] message, boolean messageIsKey, SymmetricSecretKey secretKeyForSignature) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IOException
	{
		return getAgreementAlgorithm(random, participantID, message, 0, message.length,null, 0, 0, messageIsKey, secretKeyForSignature);
	}
	public P2PLoginAgreement getAgreementAlgorithm(AbstractSecureRandom random, Serializable participantID, byte[] message, int offset, int len, byte salt[],
			int offset_salt, int len_salt, boolean messageIsKey, SymmetricSecretKey secretKeyForSignature) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IOException
	{
		switch(this)
		{
		case AGREEMENT_WITH_SIGNATURE:
			return new P2PLoginWithSignature(secretKeyForSignature, random);
		case JPAKE:
			return new P2PJPAKESecretMessageExchanger(random, participantID, message, offset, len, salt, offset_salt, len_salt, messageIsKey);
		case JPAKE_AND_AGREEMENT_WITH_SIGNATURE:
			return new P2PJPakeAndLoginAgreement(random, participantID, message, offset, len, salt, offset_salt, len_salt, messageIsKey, secretKeyForSignature);
		}
		throw new IllegalAccessError(); 
	}
}

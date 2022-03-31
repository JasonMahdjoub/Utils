package com.distrimind.util.crypto;

import java.io.IOException;

/**
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 5.10.0
 */
public interface EncryptionProfileProviderWithEncryptedKeys extends EncryptionProfileProvider{

	WrappedEncryptedSymmetricSecretKey getEncryptedSecretKeyForSignature(short keyID, boolean duringDecryptionPhase) throws IOException;
	WrappedEncryptedSymmetricSecretKey getEncryptedSecretKeyForEncryption(short keyID, boolean duringDecryptionPhase) throws IOException;
	WrappedEncryptedASymmetricPrivateKey getEncryptedPrivateKeyForSignature(short keyID) throws IOException;
	KeyWrapperAlgorithm getKeyWrapperAlgorithm();
	void unloadKeyWrapperAlgorithm();



	@Override
	default  IASymmetricPrivateKey getPrivateKeyForSignature(short keyID) throws IOException
	{
		KeyWrapperAlgorithm kwa=getKeyWrapperAlgorithm();
		WrappedEncryptedASymmetricPrivateKey wk=getEncryptedPrivateKeyForSignature(keyID);
		return kwa.unwrap(wk);
	}

	@Override
	default  SymmetricSecretKey getSecretKeyForSignature(short keyID, boolean duringDecryptionPhase) throws IOException
	{
		KeyWrapperAlgorithm kwa=getKeyWrapperAlgorithm();
		WrappedEncryptedSymmetricSecretKey wk=getEncryptedSecretKeyForSignature(keyID, duringDecryptionPhase);
		return kwa.unwrap(wk);
	}

	@Override
	default SymmetricSecretKey getSecretKeyForEncryption(short keyID, boolean duringDecryptionPhase) throws IOException
	{
		KeyWrapperAlgorithm kwa=getKeyWrapperAlgorithm();
		WrappedEncryptedSymmetricSecretKey wk=getEncryptedSecretKeyForEncryption(keyID, duringDecryptionPhase);
		return kwa.unwrap(wk);

	}

	@Override
	default void lock()
	{
		unloadKeyWrapperAlgorithm();
	}

	@Override
	default  void unlock()
	{
		getKeyWrapperAlgorithm();
	}

	@Override
	default  boolean isLockable() {
		return true;
	}
}

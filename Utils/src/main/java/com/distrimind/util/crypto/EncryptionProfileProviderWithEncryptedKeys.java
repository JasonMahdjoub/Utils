package com.distrimind.util.crypto;

import java.io.IOException;

/**
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 5.10.0
 */
public abstract class EncryptionProfileProviderWithEncryptedKeys implements EncryptionProfileProvider{

	private KeyWrapperAlgorithm keyWrapperAlgorithm=null;

	public abstract WrappedEncryptedSymmetricSecretKey getEncryptedSecretKeyForSignature(short keyID, boolean duringDecryptionPhase);
	public abstract WrappedEncryptedSymmetricSecretKey getEncryptedSecretKeyForEncryption(short keyID, boolean duringDecryptionPhase);
	public abstract WrappedEncryptedASymmetricPrivateKey getEncryptedPrivateKeyForSignature(short keyID);
	public abstract KeyWrapperAlgorithm getKeyWrapperAlgorithm();

	private KeyWrapperAlgorithm loadKeyWrapperAlgorithm()
	{
		if (keyWrapperAlgorithm==null)
			keyWrapperAlgorithm=getKeyWrapperAlgorithm();
		return keyWrapperAlgorithm;
	}


	@Override
	public IASymmetricPrivateKey getPrivateKeyForSignature(short keyID) throws IOException
	{
		KeyWrapperAlgorithm kwa=loadKeyWrapperAlgorithm();
		WrappedEncryptedASymmetricPrivateKey wk=getEncryptedPrivateKeyForSignature(keyID);
		return kwa.unwrap(wk);
	}

	@Override
	public SymmetricSecretKey getSecretKeyForSignature(short keyID, boolean duringDecryptionPhase) throws IOException
	{
		KeyWrapperAlgorithm kwa=loadKeyWrapperAlgorithm();
		WrappedEncryptedSymmetricSecretKey wk=getEncryptedSecretKeyForSignature(keyID, duringDecryptionPhase);
		return kwa.unwrap(wk);
	}

	@Override
	public SymmetricSecretKey getSecretKeyForEncryption(short keyID, boolean duringDecryptionPhase) throws IOException
	{
		KeyWrapperAlgorithm kwa=loadKeyWrapperAlgorithm();
		WrappedEncryptedSymmetricSecretKey wk=getEncryptedSecretKeyForEncryption(keyID, duringDecryptionPhase);
		return kwa.unwrap(wk);

	}

	public void lock()
	{
		keyWrapperAlgorithm=null;
	}

	@Override
	public void unlock()
	{
		loadKeyWrapperAlgorithm();
	}

	@Override
	public final boolean isLockable() {
		return true;
	}
}

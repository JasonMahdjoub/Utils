package com.distrimind.util.crypto;

import com.distrimind.util.io.Integrity;
import com.distrimind.util.io.MessageExternalizationException;

import java.io.IOException;

/**
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 5.10.0
 */
public final class SessionLockableEncryptionProfileProvider implements EncryptionProfileProvider {
	private static final long MIN_UNLOCK_DURATION_IN_MS=2000;
	private long lastUnlockTimeUTCInMs;
	private final long unlockDurationInMs;
	private final boolean permitLiveUnlock;
	private final EncryptionProfileProvider encryptionProfileProvider;


	public SessionLockableEncryptionProfileProvider(EncryptionProfileProvider encryptionProfileProvider, long unlockDurationInMs, boolean permitLiveUnlock) {
		if (encryptionProfileProvider==null)
			throw new NullPointerException();
		if (unlockDurationInMs<MIN_UNLOCK_DURATION_IN_MS)
			unlockDurationInMs=MIN_UNLOCK_DURATION_IN_MS;
		lastUnlockTimeUTCInMs=Long.MIN_VALUE;
		this.unlockDurationInMs=unlockDurationInMs;
		this.permitLiveUnlock=permitLiveUnlock;
		this.encryptionProfileProvider=encryptionProfileProvider;
	}

	private void checkProviderLocked() throws MessageExternalizationException {
		if (isProviderLocked()) {
			if (permitLiveUnlock) {
				unlock();
			}
			else
				throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN);
		}
	}


	@Override
	public IASymmetricPrivateKey getPrivateKeyForSignature(short keyID) throws IOException
	{
		checkProviderLocked();
		return encryptionProfileProvider.getPrivateKeyForSignature(keyID);
	}


	@Override
	public SymmetricSecretKey getSecretKeyForSignature(short keyID, boolean duringDecryptionPhase) throws IOException
	{
		if (!duringDecryptionPhase)
			checkProviderLocked();
		return encryptionProfileProvider.getSecretKeyForSignature(keyID, duringDecryptionPhase);
	}
	@Override
	public SymmetricSecretKey getSecretKeyForEncryption(short keyID, boolean duringDecryptionPhase) throws IOException
	{
		if (!duringDecryptionPhase)
			checkProviderLocked();
		return encryptionProfileProvider.getSecretKeyForEncryption(keyID, duringDecryptionPhase);
	}

	@Override
	public boolean isValidProfileID(short id) {
		return encryptionProfileProvider.isValidProfileID(id);
	}

	@Override
	public MessageDigestType getMessageDigest(short keyID, boolean duringDecryptionPhase) throws IOException {
		return encryptionProfileProvider.getMessageDigest(keyID, duringDecryptionPhase);
	}

	@Override
	public IASymmetricPublicKey getPublicKeyForSignature(short keyID) throws IOException {
		return encryptionProfileProvider.getPublicKeyForSignature(keyID);
	}

	@Override
	public short getDefaultKeyID() {
		return encryptionProfileProvider.getDefaultKeyID();
	}

	@Override
	public Short getValidProfileIDFromPublicKeyForSignature(IASymmetricPublicKey publicKeyForSignature) {
		return encryptionProfileProvider.getValidProfileIDFromPublicKeyForSignature(publicKeyForSignature);
	}

	@Override
	public void unlock() {
		encryptionProfileProvider.unlock();
		lastUnlockTimeUTCInMs=System.currentTimeMillis();
	}

	@Override
	public boolean isLockable() {
		return true;
	}


	@Override
	public boolean isProviderLocked() {
		return System.currentTimeMillis() - unlockDurationInMs >= lastUnlockTimeUTCInMs;
	}

	@Override
	public void lock()
	{
		encryptionProfileProvider.lock();
		lastUnlockTimeUTCInMs=Long.MIN_VALUE;
	}


}

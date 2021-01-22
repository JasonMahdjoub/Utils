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


	protected SessionLockableEncryptionProfileProvider(EncryptionProfileProvider encryptionProfileProvider, long unlockDurationInMs, boolean permitLiveUnlock) {
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
	public final IASymmetricPrivateKey getPrivateKeyForSignature(short keyID) throws IOException
	{
		checkProviderLocked();
		return encryptionProfileProvider.getPrivateKeyForSignature(keyID);
	}


	@Override
	public final SymmetricSecretKey getSecretKeyForSignature(short keyID, boolean duringDecryptionPhase) throws IOException
	{
		if (!duringDecryptionPhase)
			checkProviderLocked();
		return encryptionProfileProvider.getSecretKeyForSignature(keyID, duringDecryptionPhase);
	}
	@Override
	public final SymmetricSecretKey getSecretKeyForEncryption(short keyID, boolean duringDecryptionPhase) throws IOException
	{
		if (!duringDecryptionPhase)
			checkProviderLocked();
		return encryptionProfileProvider.getSecretKeyForEncryption(keyID, duringDecryptionPhase);
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
	public Short getValidKeyID(IASymmetricPublicKey publicKeyForSignature) {
		return encryptionProfileProvider.getValidKeyID(publicKeyForSignature);
	}

	@Override
	public final void unlock() {
		encryptionProfileProvider.unlock();
		lastUnlockTimeUTCInMs=System.currentTimeMillis();
	}

	@Override
	public final boolean isLockable() {
		return true;
	}


	@Override
	public final boolean isProviderLocked() {
		return System.currentTimeMillis() - unlockDurationInMs >= lastUnlockTimeUTCInMs;
	}

	@Override
	public final void lock()
	{
		encryptionProfileProvider.lock();
		lastUnlockTimeUTCInMs=Long.MIN_VALUE;
	}


}

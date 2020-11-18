package com.distrimind.util.crypto;

import com.distrimind.util.io.Integrity;
import com.distrimind.util.io.MessageExternalizationException;

import java.io.IOException;

/**
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 5.10.0
 */
public abstract class LockableEncryptionProfileProvider implements EncryptionProfileProvider {
	private static final long MIN_UNLOCK_DURATION_IN_MS=2000;
	private long lastUnlockTimeUTCInMs;
	private final long unlockDurationInMs;
	private final boolean permitLiveUnlock;

	protected LockableEncryptionProfileProvider(long unlockDurationInMs, boolean permitLiveUnlock) {
		if (unlockDurationInMs<MIN_UNLOCK_DURATION_IN_MS)
			unlockDurationInMs=MIN_UNLOCK_DURATION_IN_MS;
		lastUnlockTimeUTCInMs=Long.MIN_VALUE;
		this.unlockDurationInMs=unlockDurationInMs;
		this.permitLiveUnlock=permitLiveUnlock;
	}

	private void checkProviderLocked() throws MessageExternalizationException {
		if (isProviderLocked()) {
			if (permitLiveUnlock) {
				try {
					unlock();
				} catch (IOException e) {
					throw new MessageExternalizationException(Integrity.FAIL, e);
				}
			}
			else
				throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN);
		}
	}



	protected abstract IASymmetricPrivateKey getProtectedPrivateKeyForSignature(short keyID) throws IOException;

	protected abstract SymmetricSecretKey getProtectedSecretKeyForSignature(short keyID, boolean duringDecryptionPhase) throws IOException;
	protected abstract SymmetricSecretKey getProtectedSecretKeyForEncryption(short keyID, boolean duringDecryptionPhase) throws IOException;



	@Override
	public final IASymmetricPrivateKey getPrivateKeyForSignature(short keyID) throws IOException
	{
		checkProviderLocked();
		return getProtectedPrivateKeyForSignature(keyID);
	}


	@Override
	public final SymmetricSecretKey getSecretKeyForSignature(short keyID, boolean duringDecryptionPhase) throws IOException
	{
		if (!duringDecryptionPhase)
			checkProviderLocked();
		return getProtectedSecretKeyForSignature(keyID, duringDecryptionPhase);
	}
	@Override
	public final SymmetricSecretKey getSecretKeyForEncryption(short keyID, boolean duringDecryptionPhase) throws IOException
	{
		if (!duringDecryptionPhase)
			checkProviderLocked();
		return getProtectedSecretKeyForEncryption(keyID, duringDecryptionPhase);
	}


	public abstract void unlockImpl() throws IOException;
	public abstract void lockImpl();
	public abstract boolean isProviderLockedImpl();

	public final void unlock() throws IOException {
		unlockImpl();
		lastUnlockTimeUTCInMs=System.currentTimeMillis();
	}

	@Override
	public final boolean isLockable() {
		return true;
	}


	@Override
	public final boolean isProviderLocked() {
		return isProviderLockedImpl() || System.currentTimeMillis() - unlockDurationInMs >= lastUnlockTimeUTCInMs;
	}

	@Override
	public final void lock()
	{
		lockImpl();
		lastUnlockTimeUTCInMs=Long.MIN_VALUE;
	}
}

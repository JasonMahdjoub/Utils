package com.distrimind.util.crypto;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

/**
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 5.16.0
 */
public class P2PLoginWithAsymmetricSignature extends AbstractP2PLoginWithSignature {
	private final IASymmetricPrivateKey myPrivateKey;
	private final IASymmetricPublicKey otherPublicKey;

	public P2PLoginWithAsymmetricSignature(AbstractSecureRandom random, IASymmetricPrivateKey myPrivateKey, IASymmetricPublicKey otherPublicKey) {
		super(random);
		if (myPrivateKey==null)
			throw new NullPointerException();
		if (otherPublicKey==null)
			throw new NullPointerException();

		this.myPrivateKey = myPrivateKey;
		this.otherPublicKey = otherPublicKey;
	}

	@Override
	protected AbstractAuthenticatedSignerAlgorithm getSigner() throws NoSuchProviderException, NoSuchAlgorithmException, IOException {
		return new ASymmetricAuthenticatedSignerAlgorithm(myPrivateKey);
	}

	@Override
	protected AbstractAuthenticatedCheckerAlgorithm getChecker() throws NoSuchProviderException, NoSuchAlgorithmException {
		return new ASymmetricAuthenticatedSignatureCheckerAlgorithm(otherPublicKey);
	}

	@Override
	public boolean isPostQuantumAgreement() {
		return myPrivateKey.isPostQuantumKey() && otherPublicKey.isPostQuantumKey();
	}
}

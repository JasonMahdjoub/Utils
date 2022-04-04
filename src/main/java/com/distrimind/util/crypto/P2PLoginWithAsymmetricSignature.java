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

	public P2PLoginWithAsymmetricSignature(AbstractSecureRandom random, IASymmetricPrivateKey myPrivateKey, IASymmetricPublicKey otherPublicKey) throws NoSuchAlgorithmException, IOException, NoSuchProviderException {
		super(random, new ASymmetricAuthenticatedSignerAlgorithm(myPrivateKey), new ASymmetricAuthenticatedSignatureCheckerAlgorithm(otherPublicKey));
	}

}

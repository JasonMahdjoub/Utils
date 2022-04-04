package com.distrimind.util.crypto;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

/**
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 5.16.0
 */
public class P2PUnidirectionalLoginCheckerWithAsymmetricSignature extends AbstractP2PLoginWithSignature {

	public P2PUnidirectionalLoginCheckerWithAsymmetricSignature(AbstractSecureRandom random, IASymmetricPublicKey otherPublicKey) throws NoSuchAlgorithmException, NoSuchProviderException {
		super(random, null, new ASymmetricAuthenticatedSignatureCheckerAlgorithm(otherPublicKey));
	}
}

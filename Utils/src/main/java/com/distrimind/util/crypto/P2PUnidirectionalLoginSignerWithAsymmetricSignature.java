package com.distrimind.util.crypto;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

/**
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 5.16.0
 */
public class P2PUnidirectionalLoginSignerWithAsymmetricSignature extends AbstractP2PLoginWithSignature {

	public P2PUnidirectionalLoginSignerWithAsymmetricSignature(AbstractSecureRandom random, AbstractKeyPair<?,?> keyPair) throws NoSuchAlgorithmException, IOException, NoSuchProviderException {
		super(random, new ASymmetricAuthenticatedSignerAlgorithm(keyPair.getASymmetricPrivateKey()), null);

	}

}

/*
Copyright or © or Copr. Jason Mahdjoub (04/02/2016)

jason.mahdjoub@distri-mind.fr

This software (Utils) is a computer program whose purpose is to give several kind of tools for developers 
(ciphers, XML readers, decentralized id generators, etc.).

This software is governed by the CeCILL-C license under French law and
abiding by the rules of distribution of free software.  You can  use, 
modify and/ or redistribute the software under the terms of the CeCILL-C
license as circulated by CEA, CNRS and INRIA at the following URL
"http://www.cecill.info". 

As a counterpart to the access to the source code and  rights to copy,
modify and redistribute granted by the license, users are provided only
with a limited warranty  and the software's author,  the holder of the
economic rights,  and the successive licensors  have only  limited
liability. 

In this respect, the user's attention is drawn to the risks associated
with loading,  using,  modifying and/or developing or reproducing the
software by the user in light of its specific status of free software,
that may mean  that it is complicated to manipulate,  and  that  also
therefore means  that it is reserved for developers  and  experienced
professionals having in-depth computer knowledge. Users are therefore
encouraged to load and test the software's suitability as regards their
requirements in conditions enabling the security of their systems and/or 
data to be ensured and,  more generally, to use and operate it in the 
same conditions as regards security. 

The fact that you are presently reading this means that you have had
knowledge of the CeCILL-C license and that you accept its terms.
 */
package com.distrimind.util.crypto;

import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import javax.crypto.KeyAgreement;

/**
 * 
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 2.9
 */
public class EllipticCurveDiffieHellmanAlgorithm {
	private final EllipticCurveDiffieHellmanType type;
	private byte[] derivedKey;
	private KeyPair myKeyPair;
	private byte[] myPublicKeyBytes;

	EllipticCurveDiffieHellmanAlgorithm(EllipticCurveDiffieHellmanType type) {
		if (type == null)
			throw new NullPointerException();
		this.type = type;
		reset();
	}

	public void reset() {
		derivedKey = null;
		myKeyPair = null;
		myPublicKeyBytes = null;
	}

	public byte[] generateAndGetPublicKey() throws NoSuchAlgorithmException {
		reset();
		KeyPairGenerator kpg = null;
		if (type.getCodeProvider() == CodeProvider.BOUNCY_CASTLE) {
			kpg = KeyPairGenerator.getInstance("EC", CodeProvider.getBouncyProvider());
		} else
			kpg = KeyPairGenerator.getInstance("EC");
		kpg.initialize(type.getECDHKeySizeBits());
		myKeyPair = kpg.generateKeyPair();
		myPublicKeyBytes = myKeyPair.getPublic().getEncoded();

		return myPublicKeyBytes;
	}

	public void setDistantPublicKey(byte[] distantPublicKeyBytes) throws NoSuchAlgorithmException,
			InvalidKeySpecException, InvalidKeyException, gnu.vm.jgnu.security.NoSuchAlgorithmException {
		if (distantPublicKeyBytes == null)
			throw new NullPointerException();
		if (derivedKey != null)
			throw new IllegalArgumentException(
					"A key exchange process has already been begun. Use reset fonction before calling this function.");
		KeyFactory kf = null;
		if (type.getCodeProvider() == CodeProvider.BOUNCY_CASTLE) {
			kf = KeyFactory.getInstance("EC", CodeProvider.getBouncyProvider());
		} else
			kf = KeyFactory.getInstance("EC");

		X509EncodedKeySpec pkSpec = new X509EncodedKeySpec(distantPublicKeyBytes);
		PublicKey distantPublicKey = kf.generatePublic(pkSpec);

		KeyAgreement ka = null;
		if (type.getCodeProvider() == CodeProvider.BOUNCY_CASTLE)
			ka = KeyAgreement.getInstance("ECDH", CodeProvider.getBouncyProvider());
		else
			ka = KeyAgreement.getInstance("ECDH");

		ka.init(myKeyPair.getPrivate());
		ka.doPhase(distantPublicKey, true);

		byte[] sharedSecret = ka.generateSecret();

		AbstractMessageDigest hash = type.getMessageDigestType().getMessageDigestInstance();
		hash.update(sharedSecret);

		List<ByteBuffer> keys = Arrays.asList(ByteBuffer.wrap(myPublicKeyBytes),
				ByteBuffer.wrap(distantPublicKeyBytes));
		Collections.sort(keys);
		hash.update(keys.get(0));
		hash.update(keys.get(1));

		derivedKey = hash.digest();
		if (type.getKeySizeBits() == 128) {
			byte[] tab = new byte[16];
			System.arraycopy(derivedKey, 0, tab, 0, 16);
			for (int i = 0; i < 16; i++)
				tab[i] ^= derivedKey[i + 16];
			if (type.getECDHKeySizeBits() == 384)
				for (int i = 0; i < 16; i++)
					tab[i] ^= derivedKey[i + 32];

			derivedKey = tab;
		} else if (type.getKeySizeBits() == 256) {
			if (type.getECDHKeySizeBits() == 384) {
				byte[] tab = new byte[32];
				System.arraycopy(derivedKey, 0, tab, 0, 32);
				for (int i = 0; i < 16; i++)
					tab[i] ^= derivedKey[i + 32];
				derivedKey = tab;
			}
		} else {
			throw new IllegalAccessError();
		}
	}

	public SymmetricSecretKey getDerivedKey(SymmetricEncryptionType symmetricEncryptionType) {
		return symmetricEncryptionType.getSymmetricSecretKey(derivedKey, type.getKeySizeBits());
	}

}

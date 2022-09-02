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


import java.io.IOException;

/**
 * 
 * @author Jason Mahdjoub
 * @version 3.0
 * @since Utils 2.0
 */
public abstract class AbstractKeyPairGenerator {
	protected final ASymmetricEncryptionType encryptionType;
	protected final ASymmetricAuthenticatedSignatureType signatureType;

	AbstractKeyPairGenerator(ASymmetricEncryptionType type) {
		this.encryptionType = type;
		this.signatureType=null;
	}
	AbstractKeyPairGenerator(ASymmetricAuthenticatedSignatureType type) {
		this.encryptionType = null;
		this.signatureType=type;
	}

	/**
	 * Generates a key pair.
	 *
	 * <p>
	 * If this KeyPairGenerator has not been initialized explicitly,
	 * provider-specific defaults will be used for the size and other
	 * (algorithm-specific) values of the generated keys.
	 *
	 * <p>
	 * This will generate a new key pair every time it is called.
	 *
	 * <p>
	 *
	 * @return the generated key pair
	 */
	public abstract ASymmetricKeyPair generateKeyPair();

	/**
	 * Returns the standard name of the algorithm for this key pair generator. See
	 * the KeyPairGenerator section in the <a href= "{@docRoot}/../technotes/guides/security/StandardNames.html#KeyPairGenerator">
	 * Java Cryptography Architecture Standard Algorithm Name Documentation</a> for
	 * information about standard algorithm names.
	 *
	 * @return the standard string name of the algorithm.
	 */
	public abstract String getAlgorithm();

	/**
	 * Initializes the key pair generator for a certain keySize using a default
	 * parameter set and the <code>SecureRandom</code> implementation of the
	 * highest-priority installed provider as the source of randomness. (If none of
	 * the installed providers supply an implementation of
	 * <code>SecureRandom</code>, a system-provided source of randomness is used.)
	 *
	 * @param keySize
	 *            the keySize. This is an algorithm-specific metric, such as modulus
	 *            length, specified in number of bits.
	 * @param expirationTime the key expiration time
	 * @throws IOException if a problem occurs

	 */
	public abstract void initialize(int keySize, long publicKeyValidityBeginDateUTC, long expirationTime) throws IOException;

	/**
	 * Initializes the key pair generator for a certain keySize with the given
	 * source of randomness (and a default parameter set).
	 *
	 * @param keySize
	 *            the keySize. This is an algorithm-specific metric, such as modulus
	 *            length, specified in number of bits.
	 * @param expirationTime the key expiration time
	 * @param random
	 *            the source of randomness.
	 *
	 * @throws IOException if the algorithm parameters are invalid
	 * <p>
	 *
	 * @since 1.2
	 */
	public abstract void initialize(int keySize, long publicKeyValidityBeginDateUTC, long expirationTime, AbstractSecureRandom random) throws IOException;

}

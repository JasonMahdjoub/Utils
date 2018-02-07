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


import gnu.vm.jgnu.security.InvalidAlgorithmParameterException;
import gnu.vm.jgnu.security.InvalidKeyException;
import gnu.vm.jgnu.security.NoSuchAlgorithmException;
import gnu.vm.jgnu.security.spec.InvalidKeySpecException;
import gnu.vm.jgnux.crypto.SecretKey;
import gnu.vm.jgnux.crypto.ShortBufferException;

/**
 * 
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 3.10.0
 */
public abstract class AbstractKeyAgreement {
	
	
	protected final SymmetricEncryptionType encryptionType;
	protected final SymmetricAuthentifiedSignatureType signatureType;
	
	

	protected AbstractKeyAgreement(SymmetricEncryptionType encryptionType) {
		super();
		this.encryptionType = encryptionType;
		this.signatureType=null;
	}
	
	

	protected AbstractKeyAgreement(SymmetricAuthentifiedSignatureType signatureType) {
		super();
		this.encryptionType=null;
		this.signatureType = signatureType;
	}



	/**
	 * Do a phase in the key agreement. The number of times this method is called
	 * depends upon the algorithm and the number of parties involved, but must be
	 * called at least once with the <code>lastPhase</code> flag set to
	 * <code>true</code>.
	 *
	 * @param key
	 *            The key for this phase.
	 * @param lastPhase
	 *            Should be <code>true</code> if this will be the last phase before
	 *            generating the shared secret.
	 * @return The intermediate result, or <code>null</code> if there is no
	 *         intermediate result.
	 * @throws java.lang.IllegalStateException
	 *             If this instance has not been initialized.
	 * @throws java.security.InvalidKeyException
	 *             If the key is inappropriate for this algorithm.
	 */
	public abstract void doPhase(UtilKey key, boolean lastPhase) throws IllegalStateException, InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException;

	/**
	 * Generate the shared secret in a new byte array.
	 *
	 * @return The shared secret.
	 * @throws java.lang.IllegalStateException
	 *             If this instnace has not been initialized, or if not enough calls
	 *             to <code>doPhase</code> have been made.
	 */
	public abstract byte[] generateSecret() throws IllegalStateException;
		

	/**
	 * Generate the shared secret and store it into the supplied array.
	 *
	 * @param sharedSecret
	 *            The array in which to store the secret.
	 * @param offset
	 *            The index in <code>sharedSecret</code> to start storing data.
	 * @return The length of the shared secret, in bytes.
	 * @throws java.lang.IllegalStateException
	 *             If this instnace has not been initialized, or if not enough calls
	 *             to <code>doPhase</code> have been made.
	 * @throws gnu.vm.jgnux.crypto.ShortBufferException
	 *             If the supplied array is not large enough to store the result.
	 */
	public abstract int generateSecret(byte[] sharedSecret, int offset)
			throws IllegalStateException, ShortBufferException ;

	/**
	 * Generate the shared secret and return it as an appropriate {@link SecretKey}.
	 *
	 * @param keySize the key size
	 * @return The shared secret as a secret key.
	 * @throws java.lang.IllegalStateException
	 *             If this instnace has not been initialized, or if not enough calls
	 *             to <code>doPhase</code> have been made.
	 * @throws java.security.InvalidKeyException
	 *             If the shared secret cannot be used to make a {@link SecretKey}.
	 * @throws java.security.NoSuchAlgorithmException
	 *             If the specified algorithm does not exist.
	 */
	public abstract SymmetricSecretKey generateSecretKey(short keySize)
			throws IllegalStateException, InvalidKeyException, NoSuchAlgorithmException;

	/**
	 * Return the name of this key-agreement algorithm.
	 *
	 * @return The algorithm name.
	 */
	public abstract String getAlgorithm();


	
	/**
	 * Initialize this key agreement with a key, parameters, and source of
	 * randomness.
	 *
	 * @param key
	 *            The key, usually the user's private key.
	 * @param params
	 *            The algorithm parameters.
	 * @throws java.security.InvalidAlgorithmParameterException
	 *             If the supplied parameters are not appropriate.
	 * @throws java.security.InvalidKeyException
	 *             If the supplied key is not appropriate.
	 */
	public abstract void init(UtilKey key, Object params)
			throws InvalidAlgorithmParameterException, InvalidKeyException, NoSuchAlgorithmException,InvalidKeySpecException;

	
}

/*
Copyright or © or Corp. Jason Mahdjoub (04/02/2016)

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


/**
 * 
 * @author Jason Mahdjoub
 * @version 2.0
 * @since Utils 2.0
 */
public final class GnuKeyPairGenerator extends AbstractKeyPairGenerator<ASymmetricKeyPair> {
	private final Object keyPairGenerator;

	private int keySize = -1;
	private long expirationTime = -1;
	private long publicKeyValidityBeginDateUTC;

	GnuKeyPairGenerator(ASymmetricEncryptionType type, Object keyPairGenerator) {
		super(type);
		this.keyPairGenerator = keyPairGenerator;
	}
	GnuKeyPairGenerator(ASymmetricAuthenticatedSignatureType type, Object keyPairGenerator) {
		super(type);
		this.keyPairGenerator = keyPairGenerator;
	}

	@Override
	public ASymmetricKeyPair generateKeyPair() {

		Object kp = GnuFunctions.keyPairGeneratorGeneratorKeyPair(keyPairGenerator);
		if (encryptionType==null)
			return new ASymmetricKeyPair(signatureType, kp, keySize, publicKeyValidityBeginDateUTC, expirationTime);
		else
			return new ASymmetricKeyPair(encryptionType, kp, keySize, publicKeyValidityBeginDateUTC, expirationTime);
	}

	@Override
	public String getAlgorithm() {
		return GnuFunctions.keyPairGeneratorGetAlgorithm(keyPairGenerator);
	}

	@Override
	public void initialize(int keySize, long publicKeyValidityBeginDateUTC, long expirationTime) {

		GnuFunctions.keyPairGeneratorInit(keyPairGenerator, keySize);
		this.keySize = keySize;
		this.expirationTime = expirationTime;
		this.publicKeyValidityBeginDateUTC=publicKeyValidityBeginDateUTC;
	}

	@Override
	public void initialize(int keySize, long publicKeyValidityBeginDateUTC, long expirationTime, AbstractSecureRandom _random) {
		GnuFunctions.keyPairGeneratorInit(keyPairGenerator, keySize, _random);
		this.keySize = keySize;
		this.expirationTime = expirationTime;
		this.publicKeyValidityBeginDateUTC=publicKeyValidityBeginDateUTC;

	}

}

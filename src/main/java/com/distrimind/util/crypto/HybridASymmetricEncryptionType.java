package com.distrimind.util.crypto;
/*
Copyright or © or Corp. Jason Mahdjoub (01/04/2013)

jason.mahdjoub@distri-mind.fr

This software (Object Oriented Database (OOD)) is a computer program 
whose purpose is to manage a local database with the object paradigm 
and the java language

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

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Objects;

/**
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 4.5.0
 */
public final class HybridASymmetricEncryptionType {
	private final ASymmetricEncryptionType nonPQCASymmetricEncryptionType, PQCASymmetricEncryptionType;

	public HybridASymmetricEncryptionType(ASymmetricEncryptionType nonPQCASymmetricEncryptionType, ASymmetricEncryptionType PQCASymmetricEncryptionType) {
		if (nonPQCASymmetricEncryptionType==null)
			throw new NullPointerException();
		if (PQCASymmetricEncryptionType==null)
			throw new NullPointerException();
		if (nonPQCASymmetricEncryptionType.isPostQuantumAlgorithm())
			throw new IllegalArgumentException();
		if (!PQCASymmetricEncryptionType.isPostQuantumAlgorithm())
			throw new IllegalArgumentException();
		this.nonPQCASymmetricEncryptionType = nonPQCASymmetricEncryptionType;
		this.PQCASymmetricEncryptionType = PQCASymmetricEncryptionType;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;
		HybridASymmetricEncryptionType that = (HybridASymmetricEncryptionType) o;
		return nonPQCASymmetricEncryptionType.equals(that.nonPQCASymmetricEncryptionType) &&
				PQCASymmetricEncryptionType.equals(that.PQCASymmetricEncryptionType);
	}

	@Override
	public int hashCode() {
		return Objects.hash(nonPQCASymmetricEncryptionType, PQCASymmetricEncryptionType);
	}

	public ASymmetricEncryptionType getNonPQCASymmetricEncryptionType() {
		return nonPQCASymmetricEncryptionType;
	}

	public ASymmetricEncryptionType getPQCASymmetricEncryptionType() {
		return PQCASymmetricEncryptionType;
	}

	public HybridASymmetricKeyPair generateKeyPair(AbstractSecureRandom random) throws IOException, NoSuchAlgorithmException, NoSuchProviderException {
		return generateKeyPair(random, -1);
	}
	public HybridASymmetricKeyPair generateKeyPair(AbstractSecureRandom random, int keySizeBits) throws IOException, NoSuchAlgorithmException, NoSuchProviderException {
		return generateKeyPair(random, keySizeBits, System.currentTimeMillis(), System.currentTimeMillis()+nonPQCASymmetricEncryptionType.getDefaultExpirationTimeMilis());
	}
	public HybridASymmetricKeyPair generateKeyPair(AbstractSecureRandom random, int keySizeBits,
												   long publicKeyValidityBeginDateUTC, long expirationTimeUTC) throws IOException, NoSuchAlgorithmException, NoSuchProviderException {
		ASymmetricKeyPair kp=nonPQCASymmetricEncryptionType.getKeyPairGenerator(random, keySizeBits, publicKeyValidityBeginDateUTC, expirationTimeUTC ).generateKeyPair();
		ASymmetricKeyPair pqcKP=PQCASymmetricEncryptionType.getKeyPairGenerator(random, keySizeBits, publicKeyValidityBeginDateUTC, expirationTimeUTC ).generateKeyPair();
		return new HybridASymmetricKeyPair(kp, pqcKP);
	}

	@Override
	public String toString() {
		return "HybridASymmetricEncryptionType{" +
				"nonPQCASymmetricEncryptionType=" + nonPQCASymmetricEncryptionType +
				", PQCASymmetricEncryptionType=" + PQCASymmetricEncryptionType +
				'}';
	}
}

package com.distrimind.util.crypto;
/*
Copyright or © or Copr. Jason Mahdjoub (01/04/2013)

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
public final class HybridASymmetricAuthenticatedSignatureType {
	public static final int MAX_SIZE_IN_BYTES_OF_HYBRID_PUBLIC_KEY_WITH_RSA_FOR_SIGNATURE=ASymmetricAuthenticatedSignatureType.MAX_SIZE_IN_BYTES_OF_HYBRID_PUBLIC_KEY_WITH_RSA_FOR_SIGNATURE;
	public static final int MAX_SIZE_IN_BYTES_OF_HYBRID_PUBLIC_KEY_WITHOUT_RSA_FOR_SIGNATURE=ASymmetricAuthenticatedSignatureType.MAX_SIZE_IN_BYTES_OF_HYBRID_PUBLIC_KEY_WITHOUT_RSA_FOR_SIGNATURE;
	public static final int MAX_SIZE_IN_BYTES_OF_HYBRID_PUBLIC_KEY_FOR_SIGNATURE=ASymmetricAuthenticatedSignatureType.MAX_SIZE_IN_BYTES_OF_HYBRID_PUBLIC_KEY_FOR_SIGNATURE;


	public static final int MAX_SIZE_IN_BYTES_OF_HYBRID_PRIVATE_KEY_WITH_RSA_FOR_SIGNATURE=ASymmetricAuthenticatedSignatureType.MAX_SIZE_IN_BYTES_OF_HYBRID_PRIVATE_KEY_WITH_RSA_FOR_SIGNATURE;
	public static final int MAX_SIZE_IN_BYTES_OF_HYBRID_PRIVATE_KEY_WITHOUT_RSA_FOR_SIGNATURE=ASymmetricAuthenticatedSignatureType.MAX_SIZE_IN_BYTES_OF_HYBRID_PRIVATE_KEY_WITHOUT_RSA_FOR_SIGNATURE;
	public static final int MAX_SIZE_IN_BYTES_OF_HYBRID_PRIVATE_KEY_FOR_SIGNATURE=ASymmetricAuthenticatedSignatureType.MAX_SIZE_IN_BYTES_OF_HYBRID_PRIVATE_KEY_FOR_SIGNATURE;

	public static final int MAX_SIZE_IN_BYTES_OF_HYBRID_KEY_PAIR_WITH_RSA_FOR_SIGNATURE = ASymmetricAuthenticatedSignatureType.MAX_SIZE_IN_BYTES_OF_HYBRID_KEY_PAIR_WITH_RSA_FOR_SIGNATURE;
	public static final int MAX_SIZE_IN_BYTES_OF_HYBRID_KEY_PAIR_WITHOUT_RSA_FOR_SIGNATURE =ASymmetricAuthenticatedSignatureType.MAX_SIZE_IN_BYTES_OF_HYBRID_KEY_PAIR_WITHOUT_RSA_FOR_SIGNATURE;
	public static final int MAX_SIZE_IN_BYTES_OF_HYBRID_KEY_PAIR_FOR_SIGNATURE = ASymmetricAuthenticatedSignatureType.MAX_SIZE_IN_BYTES_OF_HYBRID_KEY_PAIR_FOR_SIGNATURE;

	public static final int MAX_SIZE_IN_BYTES_OF_KEY_PAIR_WITH_RSA_FOR_SIGNATURE = ASymmetricAuthenticatedSignatureType.MAX_SIZE_IN_BYTES_OF_KEY_PAIR_WITH_RSA_FOR_SIGNATURE;
	public static final int MAX_SIZE_IN_BYTES_OF_KEY_PAIR_WITHOUT_RSA_FOR_SIGNATURE =ASymmetricAuthenticatedSignatureType.MAX_SIZE_IN_BYTES_OF_KEY_PAIR_WITHOUT_RSA_FOR_SIGNATURE;
	public static final int MAX_SIZE_IN_BYTES_OF_KEY_PAIR_FOR_SIGNATURE = ASymmetricAuthenticatedSignatureType.MAX_SIZE_IN_BYTES_OF_KEY_PAIR_FOR_SIGNATURE;


	public static final int MAX_SIZE_IN_BYTES_OF_HYBRID_PUBLIC_KEY_WITH_RSA_FOR_ENCRYPTION=ASymmetricEncryptionType.MAX_SIZE_IN_BYTES_OF_HYBRID_PUBLIC_KEY_WITH_RSA_FOR_ENCRYPTION;
	public static final int MAX_SIZE_IN_BYTES_OF_HYBRID_PUBLIC_KEY_FOR_ENCRYPTION=ASymmetricEncryptionType.MAX_SIZE_IN_BYTES_OF_HYBRID_PUBLIC_KEY_FOR_ENCRYPTION;


	public static final int MAX_SIZE_IN_BYTES_OF_HYBRID_PRIVATE_KEY_WITH_RSA_FOR_ENCRYPTION=ASymmetricEncryptionType.MAX_SIZE_IN_BYTES_OF_HYBRID_PRIVATE_KEY_WITH_RSA_FOR_ENCRYPTION;
	public static final int MAX_SIZE_IN_BYTES_OF_HYBRID_PRIVATE_KEY_FOR_ENCRYPTION=ASymmetricEncryptionType.MAX_SIZE_IN_BYTES_OF_HYBRID_PRIVATE_KEY_FOR_ENCRYPTION;


	public static final int MAX_SIZE_IN_BYTES_OF_HYBRID_KEY_PAIR_WITH_RSA_FOR_ENCRYPTION = ASymmetricEncryptionType.MAX_SIZE_IN_BYTES_OF_HYBRID_KEY_PAIR_WITH_RSA_FOR_ENCRYPTION;
	public static final int MAX_SIZE_IN_BYTES_OF_HYBRID_KEY_PAIR_FOR_ENCRYPTION= ASymmetricEncryptionType.MAX_SIZE_IN_BYTES_OF_HYBRID_KEY_PAIR_FOR_ENCRYPTION;

	public static final int MAX_SIZE_IN_BYTES_OF_KEY_PAIR_WITH_RSA_FOR_ENCRYPTION = ASymmetricEncryptionType.MAX_SIZE_IN_BYTES_OF_HYBRID_KEY_PAIR_WITH_RSA_FOR_ENCRYPTION;
	public static final int MAX_SIZE_IN_BYTES_OF_KEY_PAIR_FOR_ENCRYPTION= ASymmetricEncryptionType.MAX_SIZE_IN_BYTES_OF_HYBRID_KEY_PAIR_FOR_ENCRYPTION;

	public final static int MAX_HYBRID_ASYMMETRIC_SIGNATURE_SIZE=ASymmetricAuthenticatedSignatureType.MAX_NON_PQC_ASYMMETRIC_SIGNATURE_SIZE+ASymmetricAuthenticatedSignatureType.MAX_PQC_ASYMMETRIC_SIGNATURE_SIZE;


	private final ASymmetricAuthenticatedSignatureType nonPQCASymmetricAuthenticatedSignatureType, PQCASymmetricAuthenticatedSignatureType;


	public HybridASymmetricAuthenticatedSignatureType(ASymmetricAuthenticatedSignatureType nonPQCASymmetricAuthenticatedSignatureType, ASymmetricAuthenticatedSignatureType PQCASymmetricAuthenticatedSignatureType) {
		if (nonPQCASymmetricAuthenticatedSignatureType==null)
			throw new NullPointerException();
		if (PQCASymmetricAuthenticatedSignatureType==null)
			throw new NullPointerException();
		if (nonPQCASymmetricAuthenticatedSignatureType.isPostQuantumAlgorithm())
			throw new IllegalArgumentException();
		if (!PQCASymmetricAuthenticatedSignatureType.isPostQuantumAlgorithm())
			throw new IllegalArgumentException();
		this.nonPQCASymmetricAuthenticatedSignatureType = nonPQCASymmetricAuthenticatedSignatureType;
		this.PQCASymmetricAuthenticatedSignatureType = PQCASymmetricAuthenticatedSignatureType;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;
		HybridASymmetricAuthenticatedSignatureType that = (HybridASymmetricAuthenticatedSignatureType) o;
		return nonPQCASymmetricAuthenticatedSignatureType.equals(that.nonPQCASymmetricAuthenticatedSignatureType) &&
				PQCASymmetricAuthenticatedSignatureType.equals(that.PQCASymmetricAuthenticatedSignatureType);
	}

	@Override
	public int hashCode() {
		return Objects.hash(nonPQCASymmetricAuthenticatedSignatureType, PQCASymmetricAuthenticatedSignatureType);
	}

	public ASymmetricAuthenticatedSignatureType getNonPQCASymmetricAuthenticatedSignatureType() {
		return nonPQCASymmetricAuthenticatedSignatureType;
	}

	public ASymmetricAuthenticatedSignatureType getPQCASymmetricAuthenticatedSignatureType() {
		return PQCASymmetricAuthenticatedSignatureType;
	}
	public HybridASymmetricKeyPair generateKeyPair(AbstractSecureRandom random) throws NoSuchAlgorithmException, NoSuchProviderException, IOException {
		return generateKeyPair(random, -1);
	}
	public HybridASymmetricKeyPair generateKeyPair(AbstractSecureRandom random, int keySizeBits) throws NoSuchAlgorithmException, NoSuchProviderException, IOException {
		return generateKeyPair(random, keySizeBits, Long.MAX_VALUE);
	}
	public HybridASymmetricKeyPair generateKeyPair(AbstractSecureRandom random, int keySizeBits,
												   long expirationTimeUTC) throws NoSuchAlgorithmException, NoSuchProviderException, IOException {
		ASymmetricKeyPair kp=nonPQCASymmetricAuthenticatedSignatureType.getKeyPairGenerator(random, keySizeBits, expirationTimeUTC ).generateKeyPair();
		ASymmetricKeyPair pqcKP=PQCASymmetricAuthenticatedSignatureType.getKeyPairGenerator(random, keySizeBits, expirationTimeUTC ).generateKeyPair();
		return new HybridASymmetricKeyPair(kp, pqcKP);
	}

	@Override
	public String toString() {
		return "HybridASymmetricAuthenticatedSignatureType{" +
				"nonPQCASymmetricAuthenticatedSignatureType=" + nonPQCASymmetricAuthenticatedSignatureType +
				", PQCASymmetricAuthenticatedSignatureType=" + PQCASymmetricAuthenticatedSignatureType +
				'}';
	}
}

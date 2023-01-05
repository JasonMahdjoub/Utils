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


import com.distrimind.util.data_buffers.WrappedData;
import com.distrimind.util.data_buffers.WrappedString;

import java.util.Objects;

/**
 * @author Jason Mahdjoub
 * @version 2.0
 * @since MaDKitLanEdition 4.5.0
 */
public class HybridASymmetricPublicKey extends AbstractKey implements IHybridKey, IASymmetricPublicKey{

	public static final int MAX_SIZE_IN_BYTES_OF_HYBRID_PUBLIC_KEY_WITH_RSA_FOR_SIGNATURE=ASymmetricAuthenticatedSignatureType.MAX_SIZE_IN_BYTES_OF_HYBRID_PUBLIC_KEY_WITH_RSA_FOR_SIGNATURE;
	public static final int MAX_SIZE_IN_BYTES_OF_HYBRID_PUBLIC_KEY_WITHOUT_RSA_FOR_SIGNATURE=ASymmetricAuthenticatedSignatureType.MAX_SIZE_IN_BYTES_OF_HYBRID_PUBLIC_KEY_WITHOUT_RSA_FOR_SIGNATURE;
	public static final int MAX_SIZE_IN_BYTES_OF_HYBRID_PUBLIC_KEY_FOR_SIGNATURE=ASymmetricAuthenticatedSignatureType.MAX_SIZE_IN_BYTES_OF_HYBRID_PUBLIC_KEY_FOR_SIGNATURE;

	public static final int MAX_SIZE_IN_BYTES_OF_HYBRID_PUBLIC_KEY_WITH_RSA_FOR_ENCRYPTION=ASymmetricEncryptionType.MAX_SIZE_IN_BYTES_OF_HYBRID_PUBLIC_KEY_WITH_RSA_FOR_ENCRYPTION;
	public static final int MAX_SIZE_IN_BYTES_OF_HYBRID_PUBLIC_KEY_FOR_ENCRYPTION=ASymmetricEncryptionType.MAX_SIZE_IN_BYTES_OF_HYBRID_PUBLIC_KEY_FOR_ENCRYPTION;

	public static final int MAX_SIZE_IN_BYTES_OF_HYBRID_PUBLIC_KEY=MAX_SIZE_IN_BYTES_OF_HYBRID_PUBLIC_KEY_FOR_ENCRYPTION;

	private ASymmetricPublicKey nonPQCPublicKey, PQCPublicKey;

	public HybridASymmetricPublicKey(ASymmetricPublicKey nonPQCPublicKey, ASymmetricPublicKey PQCPublicKey) {
		if (nonPQCPublicKey==null)
			throw new NullPointerException();
		if (PQCPublicKey==null)
			throw new NullPointerException();
		if ((nonPQCPublicKey.getEncryptionAlgorithmType()==null)!=(PQCPublicKey.getEncryptionAlgorithmType()==null)
				|| (nonPQCPublicKey.getAuthenticatedSignatureAlgorithmType()==null)!=(PQCPublicKey.getAuthenticatedSignatureAlgorithmType()==null))
			throw new IllegalArgumentException("The given keys must be used both for encryption or both for signature");
		if ((nonPQCPublicKey.getAuthenticatedSignatureAlgorithmType()!=null
				&& nonPQCPublicKey.getAuthenticatedSignatureAlgorithmType().isPostQuantumAlgorithm())
				|| (nonPQCPublicKey.getEncryptionAlgorithmType()!=null && nonPQCPublicKey.getEncryptionAlgorithmType().isPostQuantumAlgorithm()))
			throw new IllegalArgumentException("nonPQCPrivateKey cannot be a post quantum algorithm");
		if ((PQCPublicKey.getAuthenticatedSignatureAlgorithmType()!=null
				&& !PQCPublicKey.getAuthenticatedSignatureAlgorithmType().isPostQuantumAlgorithm())
				|| (PQCPublicKey.getEncryptionAlgorithmType()!=null && !PQCPublicKey.getEncryptionAlgorithmType().isPostQuantumAlgorithm()))
			throw new IllegalArgumentException("PQCPrivateKey must be a post quantum algorithm");
		this.nonPQCPublicKey = nonPQCPublicKey;
		this.PQCPublicKey = PQCPublicKey;
	}
	private void checkNotDestroyed()
	{
		if (isDestroyed())
			throw new IllegalAccessError();
	}
	@Override
	public WrappedString encodeString() {
		return encode().toWrappedString();
	}
	@Override
	public boolean useEncryptionAlgorithm() {
		return getNonPQCPublicKey().getEncryptionAlgorithmType()!=null;
	}

	@Override
	public boolean useAuthenticatedSignatureAlgorithm() {
		return getNonPQCPublicKey().getAuthenticatedSignatureAlgorithmType()!=null;
	}


	@Override
	public ASymmetricPublicKey getNonPQCPublicKey() {
		checkNotDestroyed();
		return nonPQCPublicKey;
	}

	public ASymmetricPublicKey getPQCPublicKey() {
		checkNotDestroyed();
		return PQCPublicKey;
	}

	@Override
	public Object toGnuKey(){
		throw new IllegalAccessError();
	}

	@Override
	public java.security.Key toJavaNativeKey() {
		throw new IllegalAccessError();
	}

	@Override
	public com.distrimind.bcfips.crypto.Key toBouncyCastleKey() {
		throw new IllegalAccessError();
	}

	public WrappedData encode() {
		return encode(true);
	}


	@Override
	public WrappedData encode(boolean includeTimes)
	{
		checkNotDestroyed();
		return AbstractKey.encodeHybridKey(nonPQCPublicKey, PQCPublicKey, includeTimes);
	}

	@Override
	public void clean() {
		nonPQCPublicKey=null;
		PQCPublicKey=null;
	}
	@Override
	public boolean isDestroyed() {
		return nonPQCPublicKey==null && PQCPublicKey==null;
	}

	@Override
	public WrappedData getKeyBytes() {
		return encode();
	}

	@Override
	public boolean isPostQuantumKey() {
		return true;
	}


	@Override
	public long getTimeExpirationUTC() {
		return Math.min(nonPQCPublicKey.getTimeExpirationUTC(), PQCPublicKey.getTimeExpirationUTC());
	}
	@Override
	public long getPublicKeyValidityBeginDateUTC() {
		return Math.max(nonPQCPublicKey.getPublicKeyValidityBeginDateUTC(), PQCPublicKey.getPublicKeyValidityBeginDateUTC());
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;
		HybridASymmetricPublicKey that = (HybridASymmetricPublicKey) o;
		return nonPQCPublicKey.equals(that.nonPQCPublicKey) &&
				PQCPublicKey.equals(that.PQCPublicKey);
	}

	@Override
	public int hashCode() {
		return Objects.hash(nonPQCPublicKey, PQCPublicKey);
	}
}

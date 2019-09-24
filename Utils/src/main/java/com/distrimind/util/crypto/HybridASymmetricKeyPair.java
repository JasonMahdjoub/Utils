package com.distrimind.util.crypto;
/*
Copyright or © or Copr. Jason Mahdjoub (01/04/2013)

jason.mahdjoub@distri-mind.fr

This software (Object Oriented Database (OOD)) is a computer program 
whose purpose is to manage a local database with the object paradigm 
and the java langage 

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

import com.distrimind.util.Bits;

import java.util.Arrays;

/**
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 4.5.0
 */
public class HybridASymmetricKeyPair extends KeyPair implements HybridKey {
	private final ASymmetricKeyPair nonPQCKeyPair, PQCKeyPair;

	public HybridASymmetricKeyPair(ASymmetricKeyPair nonPQCKeyPair, ASymmetricKeyPair PQCKeyPair) {
		if (nonPQCKeyPair==null)
			throw new NullPointerException();
		if (PQCKeyPair==null)
			throw new NullPointerException();
		if ((nonPQCKeyPair.getEncryptionAlgorithmType()==null)!=(PQCKeyPair.getEncryptionAlgorithmType()==null)
				|| (nonPQCKeyPair.getAuthentifiedSignatureAlgorithmType()==null)!=(PQCKeyPair.getAuthentifiedSignatureAlgorithmType()==null))
			throw new IllegalArgumentException("The given keys must be used both for encryption or both for signature");
		if ((nonPQCKeyPair.getAuthentifiedSignatureAlgorithmType()!=null
				&& nonPQCKeyPair.getAuthentifiedSignatureAlgorithmType().isPostQuantumAlgorithm())
				|| nonPQCKeyPair.getEncryptionAlgorithmType().isPostQuantumAlgorithm())
			throw new IllegalArgumentException("nonPQCPrivateKey cannot be a post quantum algorithm");
		if ((PQCKeyPair.getAuthentifiedSignatureAlgorithmType()!=null
				&& !PQCKeyPair.getAuthentifiedSignatureAlgorithmType().isPostQuantumAlgorithm())
				|| !PQCKeyPair.getEncryptionAlgorithmType().isPostQuantumAlgorithm())
			throw new IllegalArgumentException("PQCPrivateKey must be a post quantum algorithm");
		this.nonPQCKeyPair = nonPQCKeyPair;
		this.PQCKeyPair = PQCKeyPair;
	}

	static HybridASymmetricKeyPair decodeHybridKey(byte[] encoded, int off, int len, boolean fillArrayWithZerosWhenDecoded)
			throws IllegalArgumentException
	{
		try {
			if (off < 0 || len < 0 || len + off > encoded.length)
				throw new IllegalArgumentException();

			if (len < 68)
				throw new IllegalArgumentException();
			if (encoded[off] != Key.IS_HYBRID_KEY)
				throw new IllegalArgumentException();
			int size = (int) Bits.getPositiveInteger(encoded, off + 1, 3);
			if (size + 36 > len)
				throw new IllegalArgumentException();
			ASymmetricKeyPair nonPQCKey = ASymmetricKeyPair.decode(encoded, off + 4, size);
			if (nonPQCKey.isPostQuantumKey())
				throw new IllegalArgumentException();

			ASymmetricKeyPair PQCKey = ASymmetricKeyPair.decode(encoded, off + 4 + size, len - off - size - 4);

			if (!PQCKey.isPostQuantumKey())
				throw new IllegalArgumentException();

			return new HybridASymmetricKeyPair(nonPQCKey, PQCKey);
		}
		catch (IllegalArgumentException e)
		{
			fillArrayWithZerosWhenDecoded=false;
			throw e;
		}
		finally {
			if (fillArrayWithZerosWhenDecoded)
				Arrays.fill(encoded, off, len, (byte)0);
		}
	}


	@Override
	public byte[] encode(boolean includeTimeExpiration) {
		byte[] encodedNonPQC=nonPQCKeyPair.encode(includeTimeExpiration);
		byte[] encodedPQC=PQCKeyPair.encode(includeTimeExpiration);

		byte[] res=new byte[encodedNonPQC.length+encodedPQC.length+4];
		res[0]=Key.IS_HYBRID_KEY;
		Bits.putPositiveInteger(res, 1, encodedNonPQC.length, 3);
		System.arraycopy(encodedNonPQC, 0, res, 4, encodedNonPQC.length );
		System.arraycopy(encodedPQC, 0, res, 4+encodedNonPQC.length, encodedPQC.length );
		return res;

	}

	@Override
	public Object toGnuKeyPair()  {
		throw new IllegalAccessError();
	}

	@Override
	public java.security.KeyPair toJavaNativeKeyPair()  {
		throw new IllegalAccessError();
	}

	@Override
	public long getTimeExpirationUTC() {
		return nonPQCKeyPair.getTimeExpirationUTC();
	}

	@Override
	public void zeroize() {
		nonPQCKeyPair.zeroize();
		PQCKeyPair.zeroize();
	}


	@Override
	public boolean isPostQuantumKey() {
		return true;
	}



}

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
import java.util.Objects;

/**
 * @author Jason Mahdjoub
 * @version 2.0
 * @since Utils 4.5.0
 */
public class HybridASymmetricKeyPair extends AbstractKeyPair<HybridASymmetricPrivateKey, HybridASymmetricPublicKey> implements IHybridKey {
	private HybridASymmetricPrivateKey privateKey;
	private HybridASymmetricPublicKey publicKey;


	public HybridASymmetricKeyPair(ASymmetricKeyPair nonPQCKeyPair, ASymmetricKeyPair PQCKeyPair) {
		if (nonPQCKeyPair==null)
			throw new NullPointerException();
		if (PQCKeyPair==null)
			throw new NullPointerException();
		if ((nonPQCKeyPair.getEncryptionAlgorithmType()==null)!=(PQCKeyPair.getEncryptionAlgorithmType()==null)
				|| (nonPQCKeyPair.getAuthenticatedSignatureAlgorithmType()==null)!=(PQCKeyPair.getAuthenticatedSignatureAlgorithmType()==null))
			throw new IllegalArgumentException("The given keys must be used both for encryption or both for signature");
		if ((nonPQCKeyPair.getAuthenticatedSignatureAlgorithmType()!=null
				&& nonPQCKeyPair.getAuthenticatedSignatureAlgorithmType().isPostQuantumAlgorithm())
				|| (nonPQCKeyPair.getEncryptionAlgorithmType()!=null && nonPQCKeyPair.getEncryptionAlgorithmType().isPostQuantumAlgorithm()))
			throw new IllegalArgumentException("nonPQCPrivateKey cannot be a post quantum algorithm");
		if ((PQCKeyPair.getAuthenticatedSignatureAlgorithmType()!=null
				&& !PQCKeyPair.getAuthenticatedSignatureAlgorithmType().isPostQuantumAlgorithm())
				|| (PQCKeyPair.getEncryptionAlgorithmType()!=null && !PQCKeyPair.getEncryptionAlgorithmType().isPostQuantumAlgorithm()))
			throw new IllegalArgumentException("PQCPrivateKey must be a post quantum algorithm");
		privateKey=new HybridASymmetricPrivateKey(nonPQCKeyPair.getASymmetricPrivateKey(), PQCKeyPair.getASymmetricPrivateKey());
		publicKey=new HybridASymmetricPublicKey(nonPQCKeyPair.getASymmetricPublicKey(), PQCKeyPair.getASymmetricPublicKey());
	}
	public HybridASymmetricKeyPair(HybridASymmetricPrivateKey privateKey, HybridASymmetricPublicKey publicKey) {
		if (privateKey==null)
			throw new NullPointerException();
		if (publicKey==null)
			throw new NullPointerException();
		if ((privateKey.getNonPQCPrivateKey().getEncryptionAlgorithmType()==null)!=(publicKey.getNonPQCPublicKey().getEncryptionAlgorithmType()==null)
				|| (privateKey.getNonPQCPrivateKey().getAuthenticatedSignatureAlgorithmType()==null)!=(publicKey.getNonPQCPublicKey().getAuthenticatedSignatureAlgorithmType()==null))
			throw new IllegalArgumentException("The given keys must be used both for encryption or both for signature");
		if ((privateKey.getPQCPrivateKey().getEncryptionAlgorithmType()==null)!=(publicKey.getPQCPublicKey().getEncryptionAlgorithmType()==null)
				|| (privateKey.getPQCPrivateKey().getAuthenticatedSignatureAlgorithmType()==null)!=(publicKey.getPQCPublicKey().getAuthenticatedSignatureAlgorithmType()==null))
			throw new IllegalArgumentException("The given keys must be used both for encryption or both for signature");
		this.privateKey=privateKey;
		this.publicKey=publicKey;
	}

	static HybridASymmetricKeyPair decodeHybridKey(byte[] encoded, int off, int len, boolean fillArrayWithZerosWhenDecoded)
			throws IllegalArgumentException
	{
		try {
			if (off < 0 || len < 0 || len + off > encoded.length)
				throw new IllegalArgumentException();

			if (len < 68)
				throw new IllegalArgumentException();
			if (encoded[off] != AbstractKey.IS_HYBRID_KEY_PAIR)
				throw new IllegalArgumentException();
			int size = (int) Bits.getPositiveInteger(encoded, off + 1, 3);
			if (size + 36 > len)
				throw new IllegalArgumentException();
			IHybridKey privateKey = AbstractKey.decodeHybridKey(encoded, off + 4, size, fillArrayWithZerosWhenDecoded);
			if (!privateKey.getClass().equals(HybridASymmetricPrivateKey.class))
				throw new IllegalArgumentException();

			IHybridKey pubKey = AbstractKey.decodeHybridKey(encoded, off + 4 + size, len - size - 4, fillArrayWithZerosWhenDecoded);

			if (!pubKey.getClass().equals(HybridASymmetricPublicKey.class))
				throw new IllegalArgumentException();

			return new HybridASymmetricKeyPair((HybridASymmetricPrivateKey)privateKey, (HybridASymmetricPublicKey)pubKey);
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


	public byte[] encode() {
		return encode(true);
	}
	@Override
	public byte[] encode(boolean includeTimeExpiration)
	{

		byte[] encodedPrivKey=privateKey.encode();
		byte[] encodedPubKey=publicKey.encode(includeTimeExpiration);

		byte[] res=new byte[encodedPrivKey.length+encodedPubKey.length+4];
		res[0]= AbstractKey.IS_HYBRID_KEY_PAIR;
		Bits.putPositiveInteger(res, 1, encodedPrivKey.length, 3);
		System.arraycopy(encodedPrivKey, 0, res, 4, encodedPrivKey.length );
		System.arraycopy(encodedPubKey, 0, res, 4+encodedPrivKey.length, encodedPubKey.length );
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
		return publicKey.getTimeExpirationUTC();
	}

	@Override
	public void zeroize() {
		privateKey=null;
		publicKey=null;
	}

	/*@Override
	public ASymmetricEncryptionType getEncryptionAlgorithmType() {
		return publicKey.getEncryptionAlgorithmType();
	}

	@Override
	public ASymmetricAuthenticatedSignatureType getAuthenticatedSignatureAlgorithmType() {
		return publicKey.getAuthenticatedSignatureAlgorithmType();
	}*/

	@Override
	public HybridASymmetricPrivateKey getASymmetricPrivateKey() {
		return privateKey;
	}

	@Override
	public HybridASymmetricPublicKey getASymmetricPublicKey() {
		return publicKey;
	}

	@Override
	public boolean useEncryptionAlgorithm() {
		return publicKey.getNonPQCPublicKey().getEncryptionAlgorithmType()!=null;
	}

	@Override
	public boolean useAuthenticatedSignatureAlgorithm() {
		return publicKey.getNonPQCPublicKey().getAuthenticatedSignatureAlgorithmType()!=null;
	}




	@Override
	public boolean isPostQuantumKey() {
		return true;
	}

	@Override
	public ASymmetricKeyPair getNonPQCKeyPair()
	{
		return new ASymmetricKeyPair(privateKey.getNonPQCPrivateKey(), publicKey.getNonPQCPublicKey());
	}

	public ASymmetricKeyPair getPQCKeyPair()
	{
		return new ASymmetricKeyPair(privateKey.getPQCPrivateKey(), publicKey.getPQCPublicKey());
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;
		HybridASymmetricKeyPair that = (HybridASymmetricKeyPair) o;
		return privateKey.equals(that.privateKey) &&
				publicKey.equals(that.publicKey);
	}

	@Override
	public int hashCode() {
		return Objects.hash(privateKey, publicKey);
	}
}

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

import com.distrimind.util.Bits;
import com.distrimind.util.InvalidEncodedValue;
import com.distrimind.util.data_buffers.WrappedData;
import com.distrimind.util.data_buffers.WrappedSecretData;

import java.util.Arrays;
import java.util.Objects;

/**
 * @author Jason Mahdjoub
 * @version 2.0
 * @since Utils 4.5.0
 */
public class HybridASymmetricKeyPair extends AbstractKeyPair<HybridASymmetricPrivateKey, HybridASymmetricPublicKey> implements IHybridKey {

	public static final int MAX_SIZE_IN_BYTES_OF_HYBRID_KEY_PAIR_WITH_RSA_FOR_SIGNATURE = ASymmetricAuthenticatedSignatureType.MAX_SIZE_IN_BYTES_OF_HYBRID_KEY_PAIR_WITH_RSA_FOR_SIGNATURE;
	public static final int MAX_SIZE_IN_BYTES_OF_HYBRID_KEY_PAIR_WITHOUT_RSA_FOR_SIGNATURE =ASymmetricAuthenticatedSignatureType.MAX_SIZE_IN_BYTES_OF_HYBRID_KEY_PAIR_WITHOUT_RSA_FOR_SIGNATURE;
	public static final int MAX_SIZE_IN_BYTES_OF_HYBRID_KEY_PAIR_FOR_SIGNATURE = ASymmetricAuthenticatedSignatureType.MAX_SIZE_IN_BYTES_OF_HYBRID_KEY_PAIR_FOR_SIGNATURE;
	public static final int MAX_SIZE_IN_BYTES_OF_HYBRID_KEY_PAIR_WITH_RSA_FOR_ENCRYPTION = ASymmetricEncryptionType.MAX_SIZE_IN_BYTES_OF_HYBRID_KEY_PAIR_WITH_RSA_FOR_ENCRYPTION;
	public static final int MAX_SIZE_IN_BYTES_OF_HYBRID_KEY_PAIR_FOR_ENCRYPTION= ASymmetricEncryptionType.MAX_SIZE_IN_BYTES_OF_HYBRID_KEY_PAIR_FOR_ENCRYPTION;


	private static final class Finalizer extends Cleaner
	{
		private HybridASymmetricPrivateKey privateKey;
		private HybridASymmetricPublicKey publicKey;
		@Override
		protected void performCleanup() {
			if (privateKey!=null) {
				privateKey = null;
			}
			publicKey = null;
		}
	}
	private final Finalizer finalizer;
	private void checkNotDestroyed()
	{
		if (isCleaned())
			throw new IllegalAccessError();
	}

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
		finalizer=new Finalizer();
		finalizer.privateKey=new HybridASymmetricPrivateKey(nonPQCKeyPair.getASymmetricPrivateKey(), PQCKeyPair.getASymmetricPrivateKey());
		finalizer.publicKey=new HybridASymmetricPublicKey(nonPQCKeyPair.getASymmetricPublicKey(), PQCKeyPair.getASymmetricPublicKey());
		registerCleaner(finalizer);
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
		finalizer=new Finalizer();
		this.finalizer.privateKey=privateKey;
		this.finalizer.publicKey=publicKey;
		registerCleaner(finalizer);
	}

	static HybridASymmetricKeyPair decodeHybridKey(byte[] encoded, int off, int len, boolean fillArrayWithZerosWhenDecoded)
			throws InvalidEncodedValue
	{
		try {
			if (off < 0 || len < 0 || len + off > encoded.length)
				throw new IllegalArgumentException();
			try {
				if (len < 68)
					throw new InvalidEncodedValue();
				if (encoded[off] != AbstractKey.IS_HYBRID_KEY_PAIR)
					throw new InvalidEncodedValue();
				int size = (int) Bits.getUnsignedInt(encoded, off + 1, 3);
				if (size + 36 > len)
					throw new InvalidEncodedValue();
				IHybridKey privateKey = AbstractKey.decodeHybridKey(encoded, off + 4, size, fillArrayWithZerosWhenDecoded);
				if (!privateKey.getClass().equals(HybridASymmetricPrivateKey.class))
					throw new InvalidEncodedValue();

				IHybridKey pubKey = AbstractKey.decodeHybridKey(encoded, off + 4 + size, len - size - 4, fillArrayWithZerosWhenDecoded);

				if (!pubKey.getClass().equals(HybridASymmetricPublicKey.class))
					throw new InvalidEncodedValue();

				return new HybridASymmetricKeyPair((HybridASymmetricPrivateKey) privateKey, (HybridASymmetricPublicKey) pubKey);
			}
			catch (IllegalArgumentException e)
			{
				throw new InvalidEncodedValue(e);
			}
		}
		catch (InvalidEncodedValue | IllegalArgumentException e)
		{
			fillArrayWithZerosWhenDecoded=false;
			throw e;
		}
		finally {
			if (fillArrayWithZerosWhenDecoded)
				Arrays.fill(encoded, off, off+len, (byte)0);
		}
	}


	public WrappedSecretData encode() {
		return encode(true);
	}



	@Override
	public WrappedSecretData encode(boolean includeTimes)
	{
		checkNotDestroyed();
		WrappedSecretData encodedPrivKey=finalizer.privateKey.encode();
		WrappedData encodedPubKey=finalizer.publicKey.encode(includeTimes);

		byte[] res=new byte[encodedPrivKey.getBytes().length+encodedPubKey.getBytes().length+4];
		res[0]= AbstractKey.IS_HYBRID_KEY_PAIR;
		Bits.putUnsignedInt(res, 1, encodedPrivKey.getBytes().length, 3);
		System.arraycopy(encodedPrivKey.getBytes(), 0, res, 4, encodedPrivKey.getBytes().length );
		System.arraycopy(encodedPubKey.getBytes(), 0, res, 4+encodedPrivKey.getBytes().length, encodedPubKey.getBytes().length );
		encodedPrivKey.clean();

		return new WrappedSecretData(res);


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
		return finalizer.publicKey.getTimeExpirationUTC();
	}

	@Override
	public HybridASymmetricPrivateKey getASymmetricPrivateKey() {
		checkNotDestroyed();
		return finalizer.privateKey;
	}

	@Override
	public HybridASymmetricPublicKey getASymmetricPublicKey() {
		checkNotDestroyed();
		return finalizer.publicKey;
	}

	@Override
	public boolean useEncryptionAlgorithm() {
		return finalizer.publicKey.getNonPQCPublicKey().getEncryptionAlgorithmType()!=null;
	}

	@Override
	public boolean useAuthenticatedSignatureAlgorithm() {
		return finalizer.publicKey.getNonPQCPublicKey().getAuthenticatedSignatureAlgorithmType()!=null;
	}




	@Override
	public boolean isPostQuantumKey() {
		return true;
	}

	@Override
	public ASymmetricKeyPair getNonPQCKeyPair()
	{
		checkNotDestroyed();
		return new ASymmetricKeyPair(finalizer.privateKey.getNonPQCPrivateKey(), finalizer.publicKey.getNonPQCPublicKey());
	}

	public ASymmetricKeyPair getPQCKeyPair()
	{
		checkNotDestroyed();
		return new ASymmetricKeyPair(finalizer.privateKey.getPQCPrivateKey(), finalizer.publicKey.getPQCPublicKey());
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;
		HybridASymmetricKeyPair that = (HybridASymmetricKeyPair) o;
		return finalizer.privateKey.equals(that.finalizer.privateKey) &&
				finalizer.publicKey.equals(that.finalizer.publicKey);
	}

	@Override
	public int hashCode() {
		return Objects.hash(finalizer.privateKey, finalizer.publicKey);
	}

	@Override
	public boolean areTimesValid() {
		return finalizer.publicKey.areTimesValid();
	}
}

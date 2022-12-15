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

import com.distrimind.util.AbstractDecentralizedValue;
import com.distrimind.util.InvalidEncodedValue;
import com.distrimind.util.data_buffers.WrappedSecretData;
import com.distrimind.util.data_buffers.WrappedSecretString;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

/**
 * @author Jason Mahdjoub
 * @version 1.0
 * @since MaDKitLanEdition 4.5.0
 */
public abstract class AbstractKeyPair<TPrivateKey extends IASymmetricPrivateKey, PubKey extends IASymmetricPublicKey> extends AbstractDecentralizedValue implements ISecretDecentralizedValue {

	public static final int MAX_SIZE_IN_BYTES_OF_KEY_PAIR_WITH_RSA_FOR_SIGNATURE = ASymmetricAuthenticatedSignatureType.MAX_SIZE_IN_BYTES_OF_HYBRID_KEY_PAIR_WITH_RSA_FOR_SIGNATURE;
	public static final int MAX_SIZE_IN_BYTES_OF_KEY_PAIR_WITHOUT_RSA_FOR_SIGNATURE =ASymmetricAuthenticatedSignatureType.MAX_SIZE_IN_BYTES_OF_HYBRID_KEY_PAIR_WITHOUT_RSA_FOR_SIGNATURE;
	public static final int MAX_SIZE_IN_BYTES_OF_KEY_PAIR_FOR_SIGNATURE = ASymmetricAuthenticatedSignatureType.MAX_SIZE_IN_BYTES_OF_HYBRID_KEY_PAIR_FOR_SIGNATURE;
	public static final int MAX_SIZE_IN_BYTES_OF_KEY_PAIR_WITH_RSA_FOR_ENCRYPTION = ASymmetricEncryptionType.MAX_SIZE_IN_BYTES_OF_HYBRID_KEY_PAIR_WITH_RSA_FOR_ENCRYPTION;
	public static final int MAX_SIZE_IN_BYTES_OF_KEY_PAIR_FOR_ENCRYPTION= ASymmetricEncryptionType.MAX_SIZE_IN_BYTES_OF_HYBRID_KEY_PAIR_FOR_ENCRYPTION;

	public static AbstractKeyPair<?, ?> decode(WrappedSecretData b) throws InvalidEncodedValue {
		return decode(b.getBytes(), false);
	}
	public static AbstractKeyPair<?, ?> decode(byte[] b) throws InvalidEncodedValue {
		return decode(b, true);
	}
	public static AbstractKeyPair<?, ?> decode(byte[] b, int off, int len) throws InvalidEncodedValue {
		return decode(b, off, len,true);
	}
	public static AbstractKeyPair<?, ?> decode(byte[] b, boolean fillArrayWithZerosWhenDecoded) throws InvalidEncodedValue {
		return decode(b, 0, b.length, fillArrayWithZerosWhenDecoded);
	}
	public static AbstractKeyPair<?, ?> decode(byte[] b, int off, int len, boolean fillArrayWithZerosWhenDecoded) throws InvalidEncodedValue
	{
		if (off<0 || len<0 || len+off>b.length)
			throw new IllegalArgumentException();

		if (b[off]== AbstractKey.IS_HYBRID_KEY_PAIR) {
			return HybridASymmetricKeyPair.decodeHybridKey(b, off, len, fillArrayWithZerosWhenDecoded);
		}
		else
			return ASymmetricKeyPair.decode(b, off, len, fillArrayWithZerosWhenDecoded);
	}

	public static AbstractKeyPair<?, ?> valueOf(WrappedSecretString key) throws InvalidEncodedValue {
		return decode(new WrappedSecretData(key));
	}

	public abstract boolean isPostQuantumKey();


	public abstract Object toGnuKeyPair() throws NoSuchAlgorithmException, InvalidKeySpecException, IOException;


	public abstract java.security.KeyPair toJavaNativeKeyPair()
			throws NoSuchAlgorithmException, InvalidKeySpecException;

	public abstract long getTimeExpirationUTC();

	public static boolean isValidType(byte[] b, int off)
	{
		return b[off]== AbstractKey.IS_HYBRID_KEY_PAIR;
	}

	public abstract WrappedSecretData encode(boolean includeTimes);

	@Override
	public final WrappedSecretString encodeString() {
		return new WrappedSecretString(encode());
	}

	public abstract TPrivateKey getASymmetricPrivateKey();
	public abstract PubKey getASymmetricPublicKey();

	public abstract boolean useEncryptionAlgorithm();

	public abstract boolean useAuthenticatedSignatureAlgorithm();

	public abstract ASymmetricKeyPair getNonPQCKeyPair();

	public abstract boolean areTimesValid();

	@Override
	public String getShortClassName()
	{
		return "keyPair";
	}
}

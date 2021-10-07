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
package com.distrimind.util;

import com.distrimind.util.crypto.*;
import com.distrimind.util.data_buffers.WrappedData;
import com.distrimind.util.data_buffers.WrappedSecretData;
import com.distrimind.util.data_buffers.WrappedString;

import java.io.IOException;
import java.io.Serializable;

/**
 * @author Jason Mahdjoub
 * @version 1.1
 * @since Utils 4.3.0
 */
public interface DecentralizedValue extends Serializable {

	//int MAX_SIZE_IN_BYTES_OF_NON_HYBRID_PRIVATE_KEY = MAX_SIZE_IN_BYTES_OF_NON_HYBRID_PRIVATE_KEY_FOR_ENCRYPTION;
	int MAX_SIZE_IN_BYTES_OF_NON_HYBRID_KEY_PAIR = ASymmetricEncryptionType.MAX_SIZE_IN_BYTES_OF_NON_HYBRID_PUBLIC_KEY_FOR_ENCRYPTION + ASymmetricEncryptionType.MAX_SIZE_IN_BYTES_OF_NON_HYBRID_PRIVATE_KEY_FOR_ENCRYPTION +ASymmetricAuthenticatedSignatureType.META_DATA_SIZE_IN_BYTES_FOR_NON_HYBRID_KEY_PAIR;
	int MAX_SIZE_IN_BYTES_OF_HYBRID_KEY_PAIR= ASymmetricEncryptionType.MAX_SIZE_IN_BYTES_OF_HYBRID_PUBLIC_KEY_FOR_ENCRYPTION+ASymmetricEncryptionType.MAX_SIZE_IN_BYTES_OF_HYBRID_PRIVATE_KEY_FOR_ENCRYPTION+ASymmetricAuthenticatedSignatureType.META_DATA_SIZE_IN_BYTES_FOR_HYBRID_KEY_PAIR;
	int MAX_SIZE_IN_BYTES_OF_KEY_PAIR= MAX_SIZE_IN_BYTES_OF_HYBRID_KEY_PAIR;

	int MAX_SIZE_IN_BYTES_OF_DECENTRALIZED_VALUE= MAX_SIZE_IN_BYTES_OF_KEY_PAIR;

	WrappedData encode();
	static DecentralizedValue decode(WrappedData encodedValue)
	{
		DecentralizedValue dv=decode(encodedValue.getBytes());
		if (dv instanceof ISecretDecentralizedValue)
			encodedValue.transformToSecretData();
		return dv;
	}
	static DecentralizedValue decode(byte[] encodedValue)
	{
		return decode(encodedValue, 0, encodedValue.length);
	}

	static DecentralizedValue decode(byte[] encodedValue, int off, int len)
	{
		return decode(encodedValue, off, len, false);
	}

	static DecentralizedValue decode(byte[] encodedValue, boolean fillArrayWithZerosWhenDecoded)
	{
		return decode(encodedValue, 0, encodedValue.length, fillArrayWithZerosWhenDecoded);
	}

	static DecentralizedValue decode(byte[] encodedValue, int off, int len, boolean fillArrayWithZerosWhenDecoded)
	{
		if (AbstractDecentralizedID.isValidType(encodedValue, off))
			return AbstractDecentralizedID.decode(encodedValue, off, len, fillArrayWithZerosWhenDecoded);
		else if (AbstractKey.isValidType(encodedValue, off))
			return AbstractKey.decode(encodedValue, off, len, fillArrayWithZerosWhenDecoded);
		else
			return AbstractKeyPair.decode(encodedValue, off, len, fillArrayWithZerosWhenDecoded);

	}

	WrappedString encodeString() ;


	static DecentralizedValue valueOf(WrappedString key) throws IllegalArgumentException, IOException {
		if (key==null)
			throw new NullPointerException();
		DecentralizedValue dv=decode(new WrappedSecretData(key));
		if (dv instanceof ISecretDecentralizedValue)
			key.transformToSecretString();
		return dv;
	}


	default String toShortString()
	{
		return getShortClassName()+"[.."+encode().toShortData(8).toWrappedString().toString()+"..]";
	}

	String getShortClassName();
}

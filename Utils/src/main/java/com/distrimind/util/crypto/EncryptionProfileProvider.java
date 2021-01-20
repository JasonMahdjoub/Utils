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

/**
 * @author Jason Mahdjoub
 * @version 2.0
 * @since Utils 5.0.0
 */
public interface EncryptionProfileProvider {

	default boolean isLockable()
	{
		return false;
	}
	default boolean isProviderLocked()
	{
		return false;
	}
	default void lock()
	{

	}

	default void unlock() {

	}

	MessageDigestType getMessageDigest(short keyID, boolean duringDecryptionPhase) throws IOException;
	IASymmetricPrivateKey getPrivateKeyForSignature(short keyID) throws IOException;
	IASymmetricPublicKey getPublicKeyForSignature(short keyID) throws IOException;
	SymmetricSecretKey getSecretKeyForSignature(short keyID, boolean duringDecryptionPhase) throws IOException;
	SymmetricSecretKey getSecretKeyForEncryption(short keyID, boolean duringDecryptionPhase) throws IOException;

	Short getValidKeyID(IASymmetricPublicKey publicKeyForSignature);
	Short getValidKeyID(ASymmetricPublicKey publicKeyForSignature, boolean isHybrid);
	short getDefaultKeyID();

	default boolean useAllSignaturesKeysDuringEncoding()
	{
		return false;
	}
	default boolean checkAllSignaturesKeysDuringDecoding()
	{
		return false;
	}

	default boolean mustCheckPublicKeyValidityDuringDecoding()
	{
		return true;
	}

	default boolean canStorePartialPublicKeyDuringEncoding()
	{
		return false;
	}
	default KeyStoreModeDuringEncoding getKeyStoreModeDuringEncoding()
	{
		return KeyStoreModeDuringEncoding.ENCODE_KEY_IDENTIFIERS_AND_CHECK_THEIR_VALIDITY_DURING_DECODING;
	}

	enum KeyStoreModeDuringEncoding
	{
		ENCODE_KEY_IDENTIFIERS_AND_CHECK_THEIR_VALIDITY_DURING_DECODING,
		ENCODE_NON_PQC_PUBLIC_KEYS_WHEN_USING_HYBRID_KEYS_AND_CHECK_THEIR_VALIDITY_DURING_DECODING,
		ENCODE_ENTIRE_PUBLIC_KEYS_BUT_DO_NOT_CHECK_THEIR_VALIDITY;
	}
}

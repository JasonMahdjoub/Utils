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

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Objects;

/**
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 4.5.0
 */
public final class HybridKeyAgreementType {
	private final KeyAgreementType nonPQCKeyAgreementType, PQCKeyAgreementType;

	public HybridKeyAgreementType(KeyAgreementType nonPQCKeyAgreementType, KeyAgreementType PQCKeyAgreementType) {
		if (nonPQCKeyAgreementType==null)
			throw new NullPointerException();
		if (PQCKeyAgreementType==null)
			throw new NullPointerException();
		if (nonPQCKeyAgreementType.isPostQuantumAlgorithm())
			throw new IllegalArgumentException();
		if (!PQCKeyAgreementType.isPostQuantumAlgorithm())
			throw new IllegalArgumentException();

		this.nonPQCKeyAgreementType = nonPQCKeyAgreementType;
		this.PQCKeyAgreementType = PQCKeyAgreementType;
	}

	@Override
	public boolean equals(Object o)
	{
		if (o==null)
			return false;
		if (o.getClass()!=this.getClass())
			return false;
		HybridKeyAgreementType t=(HybridKeyAgreementType)o;
		return t.nonPQCKeyAgreementType.equals(this.nonPQCKeyAgreementType) && t.PQCKeyAgreementType.equals(this.PQCKeyAgreementType);
	}

	@Override
	public int hashCode() {
		return Objects.hash(nonPQCKeyAgreementType, PQCKeyAgreementType);
	}

	public KeyAgreementType getNonPQCKeyAgreementType() {
		return nonPQCKeyAgreementType;
	}

	public KeyAgreementType getPQCKeyAgreementType() {
		return PQCKeyAgreementType;
	}

	public KeyAgreement getKeyAgreementClient(AbstractSecureRandom randomForKeys, SymmetricAuthentifiedSignatureType signatureType) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException
	{
		return getKeyAgreementClient(randomForKeys, signatureType, (short)-1);
	}
	public KeyAgreement getKeyAgreementClient(AbstractSecureRandom randomForKeys, SymmetricAuthentifiedSignatureType signatureType, short keySizeBits) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException
	{
		return getKeyAgreementClient(randomForKeys, signatureType, keySizeBits, null);
	}
	public KeyAgreement getKeyAgreementClient(AbstractSecureRandom randomForKeys,
											  SymmetricAuthentifiedSignatureType signatureType,
											  short keySizeBits, byte[] keyingMaterial) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
		return new HybridKeyAgreement(
				nonPQCKeyAgreementType.getKeyAgreementClient(randomForKeys, signatureType, keySizeBits, keyingMaterial),
				PQCKeyAgreementType.getKeyAgreementClient(randomForKeys, signatureType, keySizeBits, keyingMaterial));
	}

	public KeyAgreement getKeyAgreementClient(AbstractSecureRandom randomForKeys, SymmetricEncryptionType encryptionType) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException
	{

		return getKeyAgreementClient(randomForKeys, encryptionType, (short)-1);
	}
	public KeyAgreement getKeyAgreementClient(AbstractSecureRandom randomForKeys, SymmetricEncryptionType encryptionType, short keySizeBits) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException
	{
		return getKeyAgreementClient(randomForKeys, encryptionType, keySizeBits, null);
	}
	public KeyAgreement getKeyAgreementClient(AbstractSecureRandom randomForKeys,
											  SymmetricEncryptionType encryptionType,
											  short keySizeBits,
											  byte[] keyingMaterial) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException
	{
		return new HybridKeyAgreement(
				nonPQCKeyAgreementType.getKeyAgreementClient(randomForKeys, encryptionType, keySizeBits, keyingMaterial),
				PQCKeyAgreementType.getKeyAgreementClient(randomForKeys, encryptionType, keySizeBits, keyingMaterial));
	}
	public KeyAgreement getKeyAgreementServer(AbstractSecureRandom randomForKeys, SymmetricAuthentifiedSignatureType signatureType) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException
	{
		return getKeyAgreementServer(randomForKeys, signatureType, (short)-1);
	}
	public KeyAgreement getKeyAgreementServer(AbstractSecureRandom randomForKeys, SymmetricAuthentifiedSignatureType signatureType, short keySizeBits) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException
	{
		return getKeyAgreementServer(randomForKeys, signatureType, keySizeBits, null);
	}
	public KeyAgreement getKeyAgreementServer(AbstractSecureRandom randomForKeys,
											  SymmetricAuthentifiedSignatureType signatureType,
											  short keySizeBits,
											  byte[] keyingMaterial) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException
	{
		return new HybridKeyAgreement(
				nonPQCKeyAgreementType.getKeyAgreementServer(randomForKeys, signatureType, keySizeBits, keyingMaterial),
				PQCKeyAgreementType.getKeyAgreementServer(randomForKeys, signatureType, keySizeBits, keyingMaterial));
	}
	public KeyAgreement getKeyAgreementServer(AbstractSecureRandom randomForKeys, SymmetricEncryptionType encryptionType) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException
	{
		return getKeyAgreementServer(randomForKeys, encryptionType, (short)-1);
	}
	public KeyAgreement getKeyAgreementServer(AbstractSecureRandom randomForKeys, SymmetricEncryptionType encryptionType, short keySizeBits) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException
	{
		return getKeyAgreementServer(randomForKeys, encryptionType, keySizeBits, null);
	}
	public KeyAgreement getKeyAgreementServer(AbstractSecureRandom randomForKeys,
											  SymmetricEncryptionType encryptionType,
											  short keySizeBits,
											  byte[] keyingMaterial) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException
	{
		return new HybridKeyAgreement(
				nonPQCKeyAgreementType.getKeyAgreementServer(randomForKeys, encryptionType, keySizeBits, keyingMaterial),
				PQCKeyAgreementType.getKeyAgreementServer(randomForKeys, encryptionType, keySizeBits, keyingMaterial));
	}

}

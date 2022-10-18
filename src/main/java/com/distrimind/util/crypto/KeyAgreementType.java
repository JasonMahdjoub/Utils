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
package com.distrimind.util.crypto;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

/**
 * 
 * @author Jason Mahdjoub
 * @version 2.1
 * @since Utils 3.14.0
 */

public enum KeyAgreementType {
	BC_FIPS_ECDDH_384_P_384(false, false, EllipticCurveDiffieHellmanType.BC_FIPS_ECDDH_384_P_384),
	BC_FIPS_ECDDH_512_P_521(false, false, EllipticCurveDiffieHellmanType.BC_FIPS_ECDDH_512_P_521),
	BC_FIPS_XDH_X25519_WITH_SHA384CKDF(false, false, EllipticCurveDiffieHellmanType.BC_FIPS_XDH_X25519_WITH_SHA384CKDF),
	BC_FIPS_XDH_X448_WITH_SHA384CKDF(false, false, EllipticCurveDiffieHellmanType.BC_FIPS_XDH_X448_WITH_SHA384CKDF),
	BC_FIPS_XDH_X25519_WITH_SHA512CKDF(false, false, EllipticCurveDiffieHellmanType.BC_FIPS_XDH_X25519_WITH_SHA512CKDF),
	BC_FIPS_XDH_X448_WITH_SHA512CKDF(false, false, EllipticCurveDiffieHellmanType.BC_FIPS_XDH_X448_WITH_SHA512CKDF),
	BCPQC_NEW_HOPE(true, true, null),
	BC_FIPS_RSA_OAEP_WITH_PARAMETERS_SHA2_384(ASymmetricKeyWrapperType.BC_FIPS_RSA_OAEP_WITH_PARAMETERS_SHA2_384, ASymmetricAuthenticatedSignatureType.BC_FIPS_Ed25519),
	BC_FIPS_RSA_OAEP_WITH_PARAMETERS_SHA2_512(ASymmetricKeyWrapperType.BC_FIPS_RSA_OAEP_WITH_PARAMETERS_SHA2_512, ASymmetricAuthenticatedSignatureType.BC_FIPS_Ed448),
	BC_FIPS_RSA_OAEP_WITH_PARAMETERS_SHA3_384(ASymmetricKeyWrapperType.BC_FIPS_RSA_OAEP_WITH_PARAMETERS_SHA3_384, ASymmetricAuthenticatedSignatureType.BC_FIPS_Ed25519),
	BC_FIPS_RSA_OAEP_WITH_PARAMETERS_SHA3_512(ASymmetricKeyWrapperType.BC_FIPS_RSA_OAEP_WITH_PARAMETERS_SHA3_512, ASymmetricAuthenticatedSignatureType.BC_FIPS_Ed448),
	BCPQC_CRYSTALS_KYBER_512(ASymmetricKeyWrapperType.BCPQC_CRYSTALS_KYBER_512, ASymmetricAuthenticatedSignatureType.BCPQC_CHRYSTALS_DILITHIUM_2),
	BCPQC_CRYSTALS_KYBER_768(ASymmetricKeyWrapperType.BCPQC_CRYSTALS_KYBER_768, ASymmetricAuthenticatedSignatureType.BCPQC_CHRYSTALS_DILITHIUM_3),
	BCPQC_CRYSTALS_KYBER_1024(ASymmetricKeyWrapperType.BCPQC_CRYSTALS_KYBER_1024, ASymmetricAuthenticatedSignatureType.BCPQC_CHRYSTALS_DILITHIUM_5),
	BCPQC_CRYSTALS_KYBER_512_AES(ASymmetricKeyWrapperType.BCPQC_CRYSTALS_KYBER_512_AES, ASymmetricAuthenticatedSignatureType.BCPQC_CHRYSTALS_DILITHIUM_2),
	BCPQC_CRYSTALS_KYBER_768_AES(ASymmetricKeyWrapperType.BCPQC_CRYSTALS_KYBER_768_AES, ASymmetricAuthenticatedSignatureType.BCPQC_CHRYSTALS_DILITHIUM_3),
	BCPQC_CRYSTALS_KYBER_1024_AES(ASymmetricKeyWrapperType.BCPQC_CRYSTALS_KYBER_1024_AES, ASymmetricAuthenticatedSignatureType.BCPQC_CHRYSTALS_DILITHIUM_5),
	BCPQC_NTRU_HPS2048509(ASymmetricKeyWrapperType.BCPQC_NTRU_HPS2048509, ASymmetricAuthenticatedSignatureType.BCPQC_CHRYSTALS_DILITHIUM_2),
	BCPQC_NTRU_HPS2048677(ASymmetricKeyWrapperType.BCPQC_NTRU_HPS2048677, ASymmetricAuthenticatedSignatureType.BCPQC_CHRYSTALS_DILITHIUM_3),
	BCPQC_NTRU_HPS4096821(ASymmetricKeyWrapperType.BCPQC_NTRU_HPS4096821, ASymmetricAuthenticatedSignatureType.BCPQC_CHRYSTALS_DILITHIUM_5),
	BCPQC_NTRU_HRSS701(ASymmetricKeyWrapperType.BCPQC_NTRU_HRSS701, ASymmetricAuthenticatedSignatureType.BCPQC_CHRYSTALS_DILITHIUM_5),
	BCPQC_SABER_LIGHT_KEM128R3(ASymmetricKeyWrapperType.BCPQC_SABER_LIGHT_KEM128R3, ASymmetricAuthenticatedSignatureType.BCPQC_CHRYSTALS_DILITHIUM_2),
	BCPQC_SABER_LIGHT_KEM192R3(ASymmetricKeyWrapperType.BCPQC_SABER_LIGHT_KEM192R3, ASymmetricAuthenticatedSignatureType.BCPQC_CHRYSTALS_DILITHIUM_3),
	BCPQC_SABER_LIGHT_KEM256R3(ASymmetricKeyWrapperType.BCPQC_SABER_LIGHT_KEM256R3, ASymmetricAuthenticatedSignatureType.BCPQC_CHRYSTALS_DILITHIUM_5),
	BCPQC_SABER_KEM128R3(ASymmetricKeyWrapperType.BCPQC_SABER_KEM128R3, ASymmetricAuthenticatedSignatureType.BCPQC_CHRYSTALS_DILITHIUM_2),
	BCPQC_SABER_KEM192R3(ASymmetricKeyWrapperType.BCPQC_SABER_KEM192R3, ASymmetricAuthenticatedSignatureType.BCPQC_CHRYSTALS_DILITHIUM_3),
	BCPQC_SABER_KEM256R3(ASymmetricKeyWrapperType.BCPQC_SABER_KEM256R3, ASymmetricAuthenticatedSignatureType.BCPQC_CHRYSTALS_DILITHIUM_5),
	BCPQC_SABER_FIRE_KEM128R3(ASymmetricKeyWrapperType.BCPQC_SABER_FIRE_KEM128R3, ASymmetricAuthenticatedSignatureType.BCPQC_CHRYSTALS_DILITHIUM_2),
	BCPQC_SABER_FIRE_KEM192R3(ASymmetricKeyWrapperType.BCPQC_SABER_FIRE_KEM192R3, ASymmetricAuthenticatedSignatureType.BCPQC_CHRYSTALS_DILITHIUM_3),
	BCPQC_SABER_FIRE_KEM256R3(ASymmetricKeyWrapperType.BCPQC_SABER_FIRE_KEM256R3, ASymmetricAuthenticatedSignatureType.BCPQC_CHRYSTALS_DILITHIUM_5),
	HYBRID_BCPQC_NEW_HOPE_WITH_BC_FIPS_XDH_X25519_WITH_SHA384CKDF(BCPQC_NEW_HOPE, BC_FIPS_XDH_X25519_WITH_SHA384CKDF),
	HYBRID_BCPQC_NEW_HOPE_WITH_BC_FIPS_XDH_X448_WITH_SHA512CKDF(BCPQC_NEW_HOPE, BC_FIPS_XDH_X448_WITH_SHA512CKDF),
	HYBRID_BCPQC_CRYSTALS_KYBER_512_AND_BC_FIPS_RSA_OAEP_WITH_SHA3_512(ASymmetricKeyWrapperType.HYBRID_BCPQC_CRYSTALS_KYBER_512_AND_BC_FIPS_RSA_OAEP_WITH_SHA3_512, ASymmetricAuthenticatedSignatureType.BCPQC_CHRYSTALS_DILITHIUM_2),
	HYBRID_BCPQC_CRYSTALS_KYBER_768_AND_BC_FIPS_RSA_OAEP_WITH_SHA3_512(ASymmetricKeyWrapperType.HYBRID_BCPQC_CRYSTALS_KYBER_768_AND_BC_FIPS_RSA_OAEP_WITH_SHA3_512, ASymmetricAuthenticatedSignatureType.BCPQC_CHRYSTALS_DILITHIUM_3),
	HYBRID_BCPQC_CRYSTALS_KYBER_1024_AND_BC_FIPS_RSA_OAEP_WITH_SHA3_512(ASymmetricKeyWrapperType.HYBRID_BCPQC_CRYSTALS_KYBER_1024_AND_BC_FIPS_RSA_OAEP_WITH_SHA3_512, ASymmetricAuthenticatedSignatureType.BCPQC_CHRYSTALS_DILITHIUM_5),
	HYBRID_BCPQC_CRYSTALS_KYBER_512_AES_AND_BC_FIPS_RSA_OAEP_WITH_SHA3_512(ASymmetricKeyWrapperType.HYBRID_BCPQC_CRYSTALS_KYBER_512_AES_AND_BC_FIPS_RSA_OAEP_WITH_SHA3_512, ASymmetricAuthenticatedSignatureType.BCPQC_CHRYSTALS_DILITHIUM_2_AES),
	HYBRID_BCPQC_CRYSTALS_KYBER_768_AES_AND_BC_FIPS_RSA_OAEP_WITH_SHA3_512(ASymmetricKeyWrapperType.HYBRID_BCPQC_CRYSTALS_KYBER_768_AES_AND_BC_FIPS_RSA_OAEP_WITH_SHA3_512, ASymmetricAuthenticatedSignatureType.BCPQC_CHRYSTALS_DILITHIUM_3_AES),
	HYBRID_BCPQC_CRYSTALS_KYBER_1024_AES_AND_BC_FIPS_RSA_OAEP_WITH_SHA3_512(ASymmetricKeyWrapperType.HYBRID_BCPQC_CRYSTALS_KYBER_1024_AES_AND_BC_FIPS_RSA_OAEP_WITH_SHA3_512, ASymmetricAuthenticatedSignatureType.BCPQC_CHRYSTALS_DILITHIUM_5_AES),

	HYBRID_BCPQC_NTRU_HPS4096821_AND_BC_FIPS_RSA_OAEP_WITH_SHA3_512(ASymmetricKeyWrapperType.HYBRID_BCPQC_NTRU_HPS4096821_AND_BC_FIPS_RSA_OAEP_WITH_SHA3_512, ASymmetricAuthenticatedSignatureType.BCPQC_CHRYSTALS_DILITHIUM_5),
	HYBRID_BCPQC_SABER_LIGHT_KEM256R3_AND_BC_FIPS_RSA_OAEP_WITH_SHA3_512(ASymmetricKeyWrapperType.HYBRID_BCPQC_SABER_LIGHT_KEM256R3_AND_BC_FIPS_RSA_OAEP_WITH_SHA3_512, ASymmetricAuthenticatedSignatureType.BCPQC_CHRYSTALS_DILITHIUM_5),
	HYBRID_BCPQC_SABER_KEM256R3_AND_BC_FIPS_RSA_OAEP_WITH_SHA3_512(ASymmetricKeyWrapperType.HYBRID_BCPQC_SABER_KEM256R3_AND_BC_FIPS_RSA_OAEP_WITH_SHA3_512, ASymmetricAuthenticatedSignatureType.BCPQC_CHRYSTALS_DILITHIUM_5),
	HYBRID_BCPQC_SABER_FIRE_KEM256R3_AND_BC_FIPS_RSA_OAEP_WITH_SHA3_512(ASymmetricKeyWrapperType.HYBRID_BCPQC_SABER_FIRE_KEM256R3_AND_BC_FIPS_RSA_OAEP_WITH_SHA3_512, ASymmetricAuthenticatedSignatureType.BCPQC_CHRYSTALS_DILITHIUM_5),
	DEFAULT(HYBRID_BCPQC_CRYSTALS_KYBER_1024_AES_AND_BC_FIPS_RSA_OAEP_WITH_SHA3_512);

	private final boolean isPQC;
	private final boolean isNewHope;
	private final EllipticCurveDiffieHellmanType ecdhType;
	private final ASymmetricKeyWrapperType keyWrapperType;
	private final ASymmetricAuthenticatedSignatureType aSymmetricAuthenticatedSignatureType;

	private final KeyAgreementType derivedType, nonPQCKeyAgreement, PQCKeyAgreement;

	public boolean equals(KeyAgreementType type)
	{
		if (type==null)
			return false;
		return type.isPQC==this.isPQC && type.isNewHope==this.isNewHope && type.ecdhType.equals(this.ecdhType);
	}

	KeyAgreementType(KeyAgreementType type) {
		this.isPQC = type.isPQC;
		this.isNewHope = type.isNewHope;
		this.ecdhType = type.ecdhType;
		this.keyWrapperType=type.keyWrapperType;
		this.aSymmetricAuthenticatedSignatureType=type.aSymmetricAuthenticatedSignatureType;
		this.derivedType=type.derivedType;
		this.nonPQCKeyAgreement=type.nonPQCKeyAgreement;
		this.PQCKeyAgreement=type.PQCKeyAgreement;
	}
	KeyAgreementType(boolean isPQC, boolean isNewHope, EllipticCurveDiffieHellmanType ecdhType) {
		this.isPQC = (ecdhType==null || ecdhType.isPostQuantumAlgorithm()) && isPQC;
		this.isNewHope = isNewHope;
		this.ecdhType = ecdhType;
		this.keyWrapperType=null;
		this.aSymmetricAuthenticatedSignatureType=null;
		this.derivedType=this;
		this.nonPQCKeyAgreement=null;
		this.PQCKeyAgreement=null;
	}
	KeyAgreementType(ASymmetricKeyWrapperType keyWrapperType, ASymmetricAuthenticatedSignatureType aSymmetricAuthenticatedSignatureType) {
		if (keyWrapperType==null)
			throw new NullPointerException();
		if (aSymmetricAuthenticatedSignatureType==null)
			throw new NullPointerException();
		this.isPQC = keyWrapperType.isPostQuantumKeyAlgorithm();
		this.isNewHope = false;
		this.ecdhType = null;
		this.keyWrapperType=keyWrapperType;
		this.aSymmetricAuthenticatedSignatureType=aSymmetricAuthenticatedSignatureType;
		this.derivedType=this;
		this.nonPQCKeyAgreement=null;
		this.PQCKeyAgreement=null;
	}
	KeyAgreementType(KeyAgreementType PQCKeyAgreement, KeyAgreementType nonPQCKeyAgreement) {
		if (nonPQCKeyAgreement==null)
			throw new NullPointerException();
		if (PQCKeyAgreement==null)
			throw new NullPointerException();
		if (nonPQCKeyAgreement.isPQC)
			throw new IllegalArgumentException();
		if (!PQCKeyAgreement.isPQC)
			throw new IllegalArgumentException();
		this.isPQC = true;
		this.isNewHope = false;
		this.ecdhType = null;
		this.keyWrapperType=null;
		this.aSymmetricAuthenticatedSignatureType=null;
		this.derivedType=this;
		this.nonPQCKeyAgreement=nonPQCKeyAgreement;
		this.PQCKeyAgreement=PQCKeyAgreement;
	}

	public KeyAgreementType getDerivedType() {
		return derivedType;
	}

	public boolean isPostQuantumAlgorithm() {
		return isPQC;
	}
	public ISimpleKeyAgreement getKeyAgreementClient(AbstractSecureRandom randomForKeys, SymmetricAuthenticatedSignatureType signatureType) throws NoSuchAlgorithmException, NoSuchProviderException, IOException
	{
		return getKeyAgreementClient(randomForKeys, signatureType, getDefaultKeySizeBits());
	}
	public ISimpleKeyAgreement getKeyAgreementClient(AbstractSecureRandom randomForKeys, SymmetricAuthenticatedSignatureType signatureType, short keySizeBits) throws NoSuchAlgorithmException, NoSuchProviderException, IOException
	{
		return getKeyAgreementClient(randomForKeys, signatureType, keySizeBits, null);
	}
	public ISimpleKeyAgreement getKeyAgreementClient(AbstractSecureRandom randomForKeys,
													 SymmetricAuthenticatedSignatureType signatureType,
													 short keySizeBits, byte[] keyingMaterial) throws NoSuchAlgorithmException, NoSuchProviderException, IOException
	{
		if (keySizeBits < 0)
			keySizeBits = getDefaultKeySizeBits();
		if (nonPQCKeyAgreement!=null)
		{
			return new HybridKeyAgreement(nonPQCKeyAgreement.getKeyAgreementClient(randomForKeys, signatureType, keySizeBits, keyingMaterial),
					PQCKeyAgreement.getKeyAgreementClient(randomForKeys, signatureType, keySizeBits, keyingMaterial));
		}
		else {


			if (keyWrapperType != null) {
				if (keyWrapperType.isHybrid())
				{
					return new HybridKeyAgreementWithSimpleKeyWrapping(randomForKeys, keyWrapperType, ASymmetricAuthenticatedSignatureType.BC_FIPS_Ed448, aSymmetricAuthenticatedSignatureType, keySizeBits, signatureType);
				}
				else
					return new KeyAgreementWithSimpleKeyWrapping(randomForKeys, keyWrapperType, aSymmetricAuthenticatedSignatureType, keySizeBits, signatureType);
			} else if (ecdhType != null)
				return new EllipticCurveDiffieHellmanAlgorithm(randomForKeys, ecdhType, keySizeBits, keyingMaterial, signatureType);
			else if (isNewHope) {
				return new NewHopeSimpleKeyAgreementClient(signatureType, keySizeBits, randomForKeys);
			} else
				throw new InternalError();
		}
	}
	public IDualKeyAgreement getDualKeyAgreementClient(AbstractSecureRandom randomForKeys, SymmetricAuthenticatedSignatureType signatureType, SymmetricEncryptionType symmetricEncryptionType) throws NoSuchAlgorithmException, NoSuchProviderException, IOException
	{
		return getDualKeyAgreementClient(randomForKeys, signatureType, symmetricEncryptionType, getDefaultKeySizeBits());
	}
	public IDualKeyAgreement getDualKeyAgreementClient(AbstractSecureRandom randomForKeys, SymmetricAuthenticatedSignatureType signatureType, SymmetricEncryptionType symmetricEncryptionType, short keySizeBits) throws NoSuchAlgorithmException, NoSuchProviderException, IOException
	{
		return getDualKeyAgreementClient(randomForKeys, signatureType, symmetricEncryptionType, keySizeBits, null);
	}
	public IDualKeyAgreement getDualKeyAgreementClient(AbstractSecureRandom randomForKeys,
											   SymmetricAuthenticatedSignatureType signatureType, SymmetricEncryptionType symmetricEncryptionType,
											   short keySizeBits, byte[] keyingMaterial) throws NoSuchAlgorithmException, NoSuchProviderException, IOException
	{
		if (keySizeBits<0)
			keySizeBits=getDefaultKeySizeBits();

		if (nonPQCKeyAgreement!=null)
		{
			return new DualHybridKeyAgreement(nonPQCKeyAgreement.getDualKeyAgreementClient(randomForKeys, signatureType, symmetricEncryptionType, keySizeBits, keyingMaterial),
					PQCKeyAgreement.getDualKeyAgreementClient(randomForKeys, signatureType, symmetricEncryptionType, keySizeBits, keyingMaterial));
		}
		else {

			if (keyWrapperType != null) {
				if (keyWrapperType.isHybrid()) {
					return new HybridDualKeyAgreementWithWrapping(randomForKeys, keyWrapperType, ASymmetricAuthenticatedSignatureType.BC_FIPS_Ed448, aSymmetricAuthenticatedSignatureType, keySizeBits, signatureType, symmetricEncryptionType);
				} else
					return new DualKeyAgreementWithKeyWrapping(randomForKeys, keyWrapperType, aSymmetricAuthenticatedSignatureType, keySizeBits, signatureType, symmetricEncryptionType);
			} else if (ecdhType != null)
				return new DualEllipticCurveDiffieHellmanAlgorithm(randomForKeys, ecdhType, keySizeBits, keyingMaterial, signatureType, symmetricEncryptionType);
			else if (isNewHope) {
				return new DualNewHopeKeyAgreementClient(signatureType, symmetricEncryptionType, keySizeBits, randomForKeys);
			} else
				throw new InternalError();
		}
	}
	public ISimpleKeyAgreement getKeyAgreementClient(AbstractSecureRandom randomForKeys, SymmetricEncryptionType encryptionType) throws NoSuchAlgorithmException, NoSuchProviderException, IOException
	{
		
		return getKeyAgreementClient(randomForKeys, encryptionType, getDefaultKeySizeBits());
	}
	public ISimpleKeyAgreement getKeyAgreementClient(AbstractSecureRandom randomForKeys, SymmetricEncryptionType encryptionType, short keySizeBits) throws NoSuchAlgorithmException, NoSuchProviderException, IOException
	{
		return getKeyAgreementClient(randomForKeys, encryptionType, keySizeBits, null);
	}
	public ISimpleKeyAgreement getKeyAgreementClient(AbstractSecureRandom randomForKeys,
													 SymmetricEncryptionType encryptionType,
													 short keySizeBits,
													 byte[] keyingMaterial) throws NoSuchAlgorithmException, NoSuchProviderException, IOException
	{
		if (keySizeBits<0)
			keySizeBits=getDefaultKeySizeBits();
		if (nonPQCKeyAgreement!=null)
		{
			return new HybridKeyAgreement(nonPQCKeyAgreement.getKeyAgreementClient(randomForKeys, encryptionType, keySizeBits, keyingMaterial),
					PQCKeyAgreement.getKeyAgreementClient(randomForKeys, encryptionType, keySizeBits, keyingMaterial));
		}
		else {
			if (keyWrapperType != null) {
				if (keyWrapperType.isHybrid()) {
					return new HybridKeyAgreementWithSimpleKeyWrapping(randomForKeys, keyWrapperType, ASymmetricAuthenticatedSignatureType.BC_FIPS_Ed448, aSymmetricAuthenticatedSignatureType, keySizeBits, encryptionType);
				} else
					return new KeyAgreementWithSimpleKeyWrapping(randomForKeys, keyWrapperType, aSymmetricAuthenticatedSignatureType, keySizeBits, encryptionType);
			} else if (ecdhType != null)
				return new EllipticCurveDiffieHellmanAlgorithm(randomForKeys, ecdhType, keySizeBits, keyingMaterial, encryptionType);
			else if (isNewHope) {
				return new NewHopeSimpleKeyAgreementClient(encryptionType, keySizeBits, randomForKeys);
			} else
				throw new InternalError();
		}
	}
	public ISimpleKeyAgreement getKeyAgreementServer(AbstractSecureRandom randomForKeys, SymmetricAuthenticatedSignatureType signatureType) throws NoSuchAlgorithmException, NoSuchProviderException, IOException
	{
		return getKeyAgreementServer(randomForKeys, signatureType, getDefaultKeySizeBits());
	}
	public ISimpleKeyAgreement getKeyAgreementServer(AbstractSecureRandom randomForKeys, SymmetricAuthenticatedSignatureType signatureType, short keySizeBits) throws NoSuchAlgorithmException, NoSuchProviderException, IOException
	{
		return getKeyAgreementServer(randomForKeys, signatureType, keySizeBits, null);
	}
	public ISimpleKeyAgreement getKeyAgreementServer(AbstractSecureRandom randomForKeys,
													 SymmetricAuthenticatedSignatureType signatureType,
													 short keySizeBits,
													 byte[] keyingMaterial) throws NoSuchAlgorithmException, NoSuchProviderException, IOException
	{
		if (keySizeBits<0)
			keySizeBits=getDefaultKeySizeBits();
		if (nonPQCKeyAgreement!=null)
		{
			return new HybridKeyAgreement(nonPQCKeyAgreement.getKeyAgreementServer(randomForKeys, signatureType, keySizeBits, keyingMaterial),
					PQCKeyAgreement.getKeyAgreementServer(randomForKeys, signatureType, keySizeBits, keyingMaterial));
		}
		else {
			if (keyWrapperType != null) {
				if (keyWrapperType.isHybrid()) {
					return new HybridKeyAgreementWithSimpleKeyWrapping(randomForKeys, keyWrapperType, ASymmetricAuthenticatedSignatureType.BC_FIPS_Ed448, aSymmetricAuthenticatedSignatureType, keySizeBits, signatureType);
				} else
					return new KeyAgreementWithSimpleKeyWrapping(randomForKeys, keyWrapperType, aSymmetricAuthenticatedSignatureType, keySizeBits, signatureType);
			} else if (ecdhType != null)
				return new EllipticCurveDiffieHellmanAlgorithm(randomForKeys, ecdhType, keySizeBits, keyingMaterial, signatureType);
			else if (isNewHope) {
				return new NewHopeSimpleKeyAgreementServer(signatureType, keySizeBits, randomForKeys);
			} else
				throw new InternalError();
		}
	}
	public IDualKeyAgreement getDualKeyAgreementServer(AbstractSecureRandom randomForKeys, SymmetricAuthenticatedSignatureType signatureType, SymmetricEncryptionType symmetricEncryptionType) throws NoSuchAlgorithmException, NoSuchProviderException, IOException
	{
		return getDualKeyAgreementServer(randomForKeys, signatureType, symmetricEncryptionType, getDefaultKeySizeBits());
	}
	public IDualKeyAgreement getDualKeyAgreementServer(AbstractSecureRandom randomForKeys, SymmetricAuthenticatedSignatureType signatureType, SymmetricEncryptionType symmetricEncryptionType, short keySizeBits) throws NoSuchAlgorithmException, NoSuchProviderException, IOException
	{
		return getDualKeyAgreementServer(randomForKeys, signatureType, symmetricEncryptionType, keySizeBits, null);
	}
	public IDualKeyAgreement getDualKeyAgreementServer(AbstractSecureRandom randomForKeys,
											   SymmetricAuthenticatedSignatureType signatureType, SymmetricEncryptionType symmetricEncryptionType,
											   short keySizeBits,
											   byte[] keyingMaterial) throws NoSuchAlgorithmException, NoSuchProviderException, IOException
	{
		if (keySizeBits<0)
			keySizeBits=getDefaultKeySizeBits();
		if (nonPQCKeyAgreement!=null)
		{
			return new DualHybridKeyAgreement(nonPQCKeyAgreement.getDualKeyAgreementServer(randomForKeys, signatureType, symmetricEncryptionType, keySizeBits, keyingMaterial),
					PQCKeyAgreement.getDualKeyAgreementServer(randomForKeys, signatureType, symmetricEncryptionType, keySizeBits, keyingMaterial));
		}
		else {
			if (keyWrapperType != null) {
				if (keyWrapperType.isHybrid()) {
					return new HybridDualKeyAgreementWithWrapping(randomForKeys, keyWrapperType, ASymmetricAuthenticatedSignatureType.BC_FIPS_Ed448, aSymmetricAuthenticatedSignatureType, keySizeBits, signatureType, symmetricEncryptionType);
				} else
					return new DualKeyAgreementWithKeyWrapping(randomForKeys, keyWrapperType, aSymmetricAuthenticatedSignatureType, keySizeBits, signatureType, symmetricEncryptionType);
			} else if (ecdhType != null)
				return new DualEllipticCurveDiffieHellmanAlgorithm(randomForKeys, ecdhType, keySizeBits, keyingMaterial, signatureType, symmetricEncryptionType);
			else if (isNewHope) {
				return new DualNewHopeKeyAgreementServer(signatureType, symmetricEncryptionType, keySizeBits, randomForKeys);
			} else
				throw new InternalError();
		}
	}
	public ISimpleKeyAgreement getKeyAgreementServer(AbstractSecureRandom randomForKeys, SymmetricEncryptionType encryptionType) throws NoSuchAlgorithmException, NoSuchProviderException, IOException
	{
		return getKeyAgreementServer(randomForKeys, encryptionType, getDefaultKeySizeBits());
	}
	public ISimpleKeyAgreement getKeyAgreementServer(AbstractSecureRandom randomForKeys, SymmetricEncryptionType encryptionType, short keySizeBits) throws NoSuchAlgorithmException, NoSuchProviderException, IOException
	{
		return getKeyAgreementServer(randomForKeys, encryptionType, keySizeBits, null);
	}
	public ISimpleKeyAgreement getKeyAgreementServer(AbstractSecureRandom randomForKeys,
													 SymmetricEncryptionType encryptionType,
													 short keySizeBits,
													 byte[] keyingMaterial) throws NoSuchAlgorithmException, NoSuchProviderException, IOException
	{
		if (keySizeBits<0)
			keySizeBits=getDefaultKeySizeBits();
		if (nonPQCKeyAgreement!=null)
		{
			return new HybridKeyAgreement(nonPQCKeyAgreement.getKeyAgreementServer(randomForKeys, encryptionType, keySizeBits, keyingMaterial),
					PQCKeyAgreement.getKeyAgreementServer(randomForKeys, encryptionType, keySizeBits, keyingMaterial));
		}
		else {
			if (keyWrapperType != null) {
				if (keyWrapperType.isHybrid()) {
					return new HybridKeyAgreementWithSimpleKeyWrapping(randomForKeys, keyWrapperType, ASymmetricAuthenticatedSignatureType.BC_FIPS_Ed448, aSymmetricAuthenticatedSignatureType, keySizeBits, encryptionType);
				} else
					return new KeyAgreementWithSimpleKeyWrapping(randomForKeys, keyWrapperType, aSymmetricAuthenticatedSignatureType, keySizeBits, encryptionType);
			} else if (ecdhType != null)
				return new EllipticCurveDiffieHellmanAlgorithm(randomForKeys, ecdhType, keySizeBits, keyingMaterial, encryptionType);
			else if (isNewHope) {
				return new NewHopeSimpleKeyAgreementServer(encryptionType, keySizeBits, randomForKeys);
			} else
				throw new InternalError();
		}
			
	}
	
	
	public short getDefaultKeySizeBits()
	{
		if (ecdhType==null || keyWrapperType!=null)
			return 256;
		else
			return ecdhType.getKeySizeBits();
	}
	
	public CodeProvider getCodeProvider()
	{
		if (keyWrapperType!=null)
			return keyWrapperType.getCodeProvider();
		else if (ecdhType==null)
			return CodeProvider.BCPQC;
		else
			return ecdhType.getCodeProvider();
	}

	public boolean isHybrid()
	{
		return (keyWrapperType!=null && keyWrapperType.isHybrid()) || nonPQCKeyAgreement!=null;
	}
}

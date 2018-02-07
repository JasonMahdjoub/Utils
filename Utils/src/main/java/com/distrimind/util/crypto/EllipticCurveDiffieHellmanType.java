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

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import javax.crypto.KeyAgreement;

import org.bouncycastle.crypto.fips.FipsDigestAlgorithm;
import org.bouncycastle.crypto.fips.FipsKDF;
import org.bouncycastle.crypto.fips.FipsSHS;

/**
 * 
 * @author Jason Mahdjoub
 * @version 1.2
 * @since Utils 2.9
 */
public enum EllipticCurveDiffieHellmanType {
	/*ECDDH_384_AES128((short) 128, (short) 256, CodeProvider.SunRsaSign, ASymmetricAuthentifiedSignatureType.BC_SHA256withECDSA_CURVE_25519, "ECCDHwithSHA384CKDF", null, null, true),
	ECDDH_384_AES256((short) 256, (short) 384, CodeProvider.SunRsaSign, ASymmetricAuthentifiedSignatureType.BC_SHA384withECDSA_CURVE_25519, "ECCDHwithSHA384CKDF", null, null, true),
	ECDDH_512_AES256((short) 256, (short) 521, CodeProvider.SunRsaSign, ASymmetricAuthentifiedSignatureType.BC_SHA512withECDSA_CURVE_25519, "ECCDHwithSHA512CKDF", null, null, true),*/
	@Deprecated
	BC_FIPS_ECDDH_384_AES128((short) 128, (short) 256, CodeProvider.BCFIPS, ASymmetricAuthentifiedSignatureType.BC_FIPS_SHA256withECDSA, "ECCDHwithSHA384CKDF", FipsSHS.Algorithm.SHA384, FipsKDF.AgreementKDFPRF.SHA384, true),
	@Deprecated
	BC_FIPS_ECDDH_384_AES256((short) 256, (short) 384, CodeProvider.BCFIPS, ASymmetricAuthentifiedSignatureType.BC_FIPS_SHA384withECDSA, "ECCDHwithSHA384CKDF", FipsSHS.Algorithm.SHA384, FipsKDF.AgreementKDFPRF.SHA384, true),
	@Deprecated
	BC_FIPS_ECDDH_512_AES256((short) 256, (short) 521, CodeProvider.BCFIPS, ASymmetricAuthentifiedSignatureType.BC_FIPS_SHA512withECDSA, "ECCDHwithSHA512CKDF", FipsSHS.Algorithm.SHA512, FipsKDF.AgreementKDFPRF.SHA512, true), 
	BC_ECDDH_384_AES128_CURVE_25519((short) 128, (short) 256, CodeProvider.BCFIPS, ASymmetricAuthentifiedSignatureType.BC_SHA256withECDSA_CURVE_25519, "ECCDHwithSHA384CKDF", FipsSHS.Algorithm.SHA384, FipsKDF.AgreementKDFPRF.SHA384, true),
	BC_ECDDH_384_AES256_CURVE_25519((short) 256, (short) 384, CodeProvider.BCFIPS, ASymmetricAuthentifiedSignatureType.BC_SHA384withECDSA_CURVE_25519, "ECCDHwithSHA384CKDF", FipsSHS.Algorithm.SHA384, FipsKDF.AgreementKDFPRF.SHA384, true),
	BC_ECDDH_512_AES256_CURVE_25519((short) 256, (short) 521, CodeProvider.BCFIPS, ASymmetricAuthentifiedSignatureType.BC_SHA512withECDSA_CURVE_25519, "ECCDHwithSHA512CKDF", FipsSHS.Algorithm.SHA512, FipsKDF.AgreementKDFPRF.SHA512, true), 
	BC_ECDDH_384_AES128_CURVE_M_221((short) 128, (short) 256, CodeProvider.BCFIPS, ASymmetricAuthentifiedSignatureType.BC_SHA256withECDSA_CURVE_M_221, "ECCDHwithSHA384CKDF", FipsSHS.Algorithm.SHA384, FipsKDF.AgreementKDFPRF.SHA384, true),
	BC_ECDDH_384_AES256_CURVE_M_221((short) 256, (short) 384, CodeProvider.BCFIPS, ASymmetricAuthentifiedSignatureType.BC_SHA384withECDSA_CURVE_M_221, "ECCDHwithSHA384CKDF", FipsSHS.Algorithm.SHA384, FipsKDF.AgreementKDFPRF.SHA384, true),
	BC_ECDDH_512_AES256_CURVE_M_221((short) 256, (short) 521, CodeProvider.BCFIPS, ASymmetricAuthentifiedSignatureType.BC_SHA512withECDSA_CURVE_M_221, "ECCDHwithSHA512CKDF", FipsSHS.Algorithm.SHA512, FipsKDF.AgreementKDFPRF.SHA512, true), 
	BC_ECDDH_384_AES128_CURVE_M_383((short) 128, (short) 256, CodeProvider.BCFIPS, ASymmetricAuthentifiedSignatureType.BC_SHA256withECDSA_CURVE_M_383, "ECCDHwithSHA384CKDF", FipsSHS.Algorithm.SHA384, FipsKDF.AgreementKDFPRF.SHA384, true),
	BC_ECDDH_384_AES256_CURVE_M_383((short) 256, (short) 384, CodeProvider.BCFIPS, ASymmetricAuthentifiedSignatureType.BC_SHA384withECDSA_CURVE_M_383, "ECCDHwithSHA384CKDF", FipsSHS.Algorithm.SHA384, FipsKDF.AgreementKDFPRF.SHA384, true),
	BC_ECDDH_512_AES256_CURVE_M_383((short) 256, (short) 521, CodeProvider.BCFIPS, ASymmetricAuthentifiedSignatureType.BC_SHA512withECDSA_CURVE_M_383, "ECCDHwithSHA512CKDF", FipsSHS.Algorithm.SHA512, FipsKDF.AgreementKDFPRF.SHA512, true), 
	BC_ECDDH_384_AES128_CURVE_M_511((short) 128, (short) 256, CodeProvider.BCFIPS, ASymmetricAuthentifiedSignatureType.BC_SHA256withECDSA_CURVE_M_511, "ECCDHwithSHA384CKDF", FipsSHS.Algorithm.SHA384, FipsKDF.AgreementKDFPRF.SHA384, true),
	BC_ECDDH_384_AES256_CURVE_M_511((short) 256, (short) 384, CodeProvider.BCFIPS, ASymmetricAuthentifiedSignatureType.BC_SHA384withECDSA_CURVE_M_511, "ECCDHwithSHA384CKDF", FipsSHS.Algorithm.SHA384, FipsKDF.AgreementKDFPRF.SHA384, true),
	BC_ECDDH_512_AES256_CURVE_M_511((short) 256, (short) 521, CodeProvider.BCFIPS, ASymmetricAuthentifiedSignatureType.BC_SHA512withECDSA_CURVE_M_511, "ECCDHwithSHA512CKDF", FipsSHS.Algorithm.SHA512, FipsKDF.AgreementKDFPRF.SHA512, true), 
	BC_ECDDH_384_AES128_CURVE_41417((short) 128, (short) 256, CodeProvider.BCFIPS, ASymmetricAuthentifiedSignatureType.BC_SHA256withECDSA_CURVE_41417, "ECCDHwithSHA384CKDF", FipsSHS.Algorithm.SHA384, FipsKDF.AgreementKDFPRF.SHA384, true),
	BC_ECDDH_384_AES256_CURVE_41417((short) 256, (short) 384, CodeProvider.BCFIPS, ASymmetricAuthentifiedSignatureType.BC_SHA384withECDSA_CURVE_41417, "ECCDHwithSHA384CKDF", FipsSHS.Algorithm.SHA384, FipsKDF.AgreementKDFPRF.SHA384, true),
	BC_ECDDH_512_AES256_CURVE_41417((short) 256, (short) 521, CodeProvider.BCFIPS, ASymmetricAuthentifiedSignatureType.BC_SHA512withECDSA_CURVE_41417, "ECCDHwithSHA512CKDF", FipsSHS.Algorithm.SHA512, FipsKDF.AgreementKDFPRF.SHA512, true), 
	DEFAULT(BC_ECDDH_384_AES256_CURVE_M_511);

	private final short keySizeBits;
	private final short ECDHKeySizeBits;
	private final CodeProvider codeProvider;
	private final ASymmetricAuthentifiedSignatureType aSymmetricAuthentifiedSignatureType;
	private final String keyAgreementName;
	private final FipsDigestAlgorithm fipsDigestAlgorithm;
	private final FipsKDF.AgreementKDFPRF agreementKDFPRF;
	private final boolean useKDF;
	
	
	
	private EllipticCurveDiffieHellmanType(short keySizeBits, short ECDHKeySizeBits,
			CodeProvider codeProvider, ASymmetricAuthentifiedSignatureType aSymmetricAuthentifiedSignatureType, String keyAgreementName, FipsDigestAlgorithm fipsDigestAlgorithm, FipsKDF.AgreementKDFPRF agreementKDFPRF, boolean useKDF) {
		this.keySizeBits = keySizeBits;
		this.ECDHKeySizeBits = ECDHKeySizeBits;
		this.codeProvider = codeProvider;
		this.aSymmetricAuthentifiedSignatureType=aSymmetricAuthentifiedSignatureType;
		this.keyAgreementName=keyAgreementName;
		this.fipsDigestAlgorithm=fipsDigestAlgorithm;
		this.agreementKDFPRF=agreementKDFPRF;
		this.useKDF=useKDF;
		
	}
	
	public ASymmetricAuthentifiedSignatureType getASymmetricAuthentifiedSignatureType()
	{
		return aSymmetricAuthentifiedSignatureType;
	}

	private EllipticCurveDiffieHellmanType(EllipticCurveDiffieHellmanType other) {
		this(other.keySizeBits, other.ECDHKeySizeBits, other.codeProvider, other.aSymmetricAuthentifiedSignatureType, other.keyAgreementName, other.fipsDigestAlgorithm, other.agreementKDFPRF, other.useKDF);
	}

	public String getKeyAgreementName()
	{
		return keyAgreementName;
	}
	
	
	public short getKeySizeBits() {
		return keySizeBits;
	}

	public short getECDHKeySizeBits() {
		return ECDHKeySizeBits;
	}

	public EllipticCurveDiffieHellmanAlgorithm getInstance(AbstractSecureRandom randomForKeys) {
		return new EllipticCurveDiffieHellmanAlgorithm(randomForKeys, this);
	}

	public CodeProvider getCodeProvider() {
		return codeProvider;
	}
	
	FipsDigestAlgorithm getBCFipsDigestAlgorithm()
	{
		return fipsDigestAlgorithm;
	}
	
	FipsKDF.AgreementKDFPRF getBCFipsAgreementKDFPRF()
	{
		return agreementKDFPRF;
	}
	
	boolean useKDF()
	{
		return useKDF;
	}
	
	AbstractKeyAgreement getKeyAgreementInstance(SymmetricEncryptionType type) throws NoSuchAlgorithmException, NoSuchProviderException
	{
		if (codeProvider==CodeProvider.BC || codeProvider==CodeProvider.BCFIPS)
			return new BCKeyAgreement(type, this);
		else
			return new JavaNativeKeyAgreement(type, KeyAgreement.getInstance(getKeyAgreementName(), getCodeProvider().checkProviderWithCurrentOS().name()));		
	}
	AbstractKeyAgreement getKeyAgreementInstance(SymmetricAuthentifiedSignatureType type) throws NoSuchAlgorithmException, NoSuchProviderException
	{
		if (codeProvider==CodeProvider.BC || codeProvider==CodeProvider.BCFIPS)
			return new BCKeyAgreement(type, this);
		else
			return new JavaNativeKeyAgreement(type, KeyAgreement.getInstance(getKeyAgreementName(), getCodeProvider().checkProviderWithCurrentOS().name()));		
	}
	
}
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
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;

import javax.crypto.KeyAgreement;

import com.distrimind.bcfips.crypto.fips.FipsDigestAlgorithm;
import com.distrimind.bcfips.crypto.fips.FipsKDF;
import com.distrimind.bcfips.crypto.fips.FipsSHS;
import com.distrimind.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;

/**
 * 
 * @author Jason Mahdjoub
 * @version 3.2
 * @since Utils 2.10
 */
public enum EllipticCurveDiffieHellmanType {
	BC_FIPS_ECDDH_384_P_384((short) 256, (short) 384, CodeProvider.BCFIPS, ASymmetricAuthenticatedSignatureType.BC_FIPS_SHA384withECDSA_P_384, "ECCDHwithSHA384CKDF", FipsSHS.Algorithm.SHA384, FipsKDF.AgreementKDFPRF.SHA384, true, new ECGenParameterSpec("P-384")),
	BC_FIPS_ECDDH_512_P_521((short) 256, (short) 521, CodeProvider.BCFIPS, ASymmetricAuthenticatedSignatureType.BC_FIPS_SHA512withECDSA_P_521, "ECCDHwithSHA512CKDF", FipsSHS.Algorithm.SHA512, FipsKDF.AgreementKDFPRF.SHA512, true, new ECGenParameterSpec("P-521")),
	/*@SuppressWarnings("deprecation") BC_ECCDH_384_CURVE_25519((short) 256, (short) 384, CodeProvider.BCFIPS, ASymmetricAuthenticatedSignatureType.BC_SHA384withECDSA_CURVE_25519, "ECCDHwithSHA384CKDF", FipsSHS.Algorithm.SHA384, FipsKDF.AgreementKDFPRF.SHA384, true),
	@SuppressWarnings("deprecation") BC_ECCDH_512_CURVE_25519((short) 256, (short) 521, CodeProvider.BCFIPS, ASymmetricAuthenticatedSignatureType.BC_SHA512withECDSA_CURVE_25519, "ECCDHwithSHA512CKDF", FipsSHS.Algorithm.SHA512, FipsKDF.AgreementKDFPRF.SHA512, true),*/
	BC_FIPS_XDH_X25519_WITH_SHA384CKDF((short) 256, (short) 521, CodeProvider.BCFIPS, ASymmetricAuthenticatedSignatureType.BC_FIPS_Ed25519, "X25519", FipsSHS.Algorithm.SHA384, FipsKDF.AgreementKDFPRF.SHA384, true, new ECNamedCurveGenParameterSpec("X25519")),
	BC_FIPS_XDH_X448_WITH_SHA384CKDF((short) 256, (short) 521, CodeProvider.BCFIPS, ASymmetricAuthenticatedSignatureType.BC_FIPS_Ed448, "X448", FipsSHS.Algorithm.SHA384, FipsKDF.AgreementKDFPRF.SHA384, true, new ECNamedCurveGenParameterSpec("X448")),
	BC_FIPS_XDH_X25519_WITH_SHA512CKDF((short) 256, (short) 521, CodeProvider.BCFIPS, ASymmetricAuthenticatedSignatureType.BC_FIPS_Ed25519, "X25519", FipsSHS.Algorithm.SHA512, FipsKDF.AgreementKDFPRF.SHA512, true, new ECNamedCurveGenParameterSpec("X25519")),
	BC_FIPS_XDH_X448_WITH_SHA512CKDF((short) 256, (short) 521, CodeProvider.BCFIPS, ASymmetricAuthenticatedSignatureType.BC_FIPS_Ed448, "X448", FipsSHS.Algorithm.SHA512, FipsKDF.AgreementKDFPRF.SHA512, true, new ECNamedCurveGenParameterSpec("X448")),
	DEFAULT(BC_FIPS_XDH_X448_WITH_SHA512CKDF);

	private final short keySizeBits;
	private final short ECDHKeySizeBits;
	private final CodeProvider codeProvider;
	private final ASymmetricAuthenticatedSignatureType aSymmetricAuthenticatedSignatureType;
	private final String keyAgreementName;
	private final FipsDigestAlgorithm fipsDigestAlgorithm;
	private final FipsKDF.AgreementKDFPRF agreementKDFPRF;
	private final boolean useKDF;
	private EllipticCurveDiffieHellmanType derivedType;
	private final AlgorithmParameterSpec algorithmParameterSpecForKeyGenerator;

	
	public boolean equals(EllipticCurveDiffieHellmanType t)
	{
		if (t==null)
			return false;
		//noinspection StringEquality
		return t.codeProvider==codeProvider && t.keySizeBits==keySizeBits && t.ECDHKeySizeBits==ECDHKeySizeBits && aSymmetricAuthenticatedSignatureType ==t.aSymmetricAuthenticatedSignatureType
				&& keyAgreementName==t.keyAgreementName;
	}

	public AlgorithmParameterSpec getAlgorithmParameterSpecForKeyGenerator() {
		return algorithmParameterSpecForKeyGenerator;
	}

	EllipticCurveDiffieHellmanType(short keySizeBits, short ECDHKeySizeBits,
								   CodeProvider codeProvider, ASymmetricAuthenticatedSignatureType aSymmetricAuthenticatedSignatureType, String keyAgreementName, FipsDigestAlgorithm fipsDigestAlgorithm, FipsKDF.AgreementKDFPRF agreementKDFPRF, boolean useKDF, AlgorithmParameterSpec algorithmParameterSpecForKeyGenerator) {
		this.keySizeBits = keySizeBits;
		this.ECDHKeySizeBits = ECDHKeySizeBits;
		this.codeProvider = codeProvider;
		this.aSymmetricAuthenticatedSignatureType = aSymmetricAuthenticatedSignatureType;
		this.keyAgreementName=keyAgreementName;
		this.fipsDigestAlgorithm=fipsDigestAlgorithm;
		this.agreementKDFPRF=agreementKDFPRF;
		this.useKDF=useKDF;
		this.derivedType=this;
		this.algorithmParameterSpecForKeyGenerator = algorithmParameterSpecForKeyGenerator;
	}
	
	ASymmetricAuthenticatedSignatureType getASymmetricAuthenticatedSignatureType()
	{
		return aSymmetricAuthenticatedSignatureType;
	}

	EllipticCurveDiffieHellmanType(EllipticCurveDiffieHellmanType other) {
		this(other.keySizeBits, other.ECDHKeySizeBits, other.codeProvider, other.aSymmetricAuthenticatedSignatureType, other.keyAgreementName, other.fipsDigestAlgorithm, other.agreementKDFPRF, other.useKDF, other.algorithmParameterSpecForKeyGenerator);
		this.derivedType=other;
	}

	public String getKeyAgreementAlgorithmName()
	{
		return keyAgreementName;
	}
	
	
	public short getKeySizeBits() {
		return keySizeBits;
	}

	public short getECDHKeySizeBits() {
		return ECDHKeySizeBits;
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
		//CodeProvider.ensureProviderLoaded(codeProvider);
		if ((codeProvider==CodeProvider.BC || codeProvider==CodeProvider.BCFIPS) && !isXDHType())
			return new BCKeyAgreement(type, this);
		else
			return new JavaNativeKeyAgreement(type, KeyAgreement.getInstance(getKeyAgreementAlgorithmName(), getCodeProvider().getCompatibleProvider()));
	}
	AbstractKeyAgreement getKeyAgreementInstance(SymmetricAuthenticatedSignatureType type) throws NoSuchAlgorithmException, NoSuchProviderException
	{
		//CodeProvider.ensureProviderLoaded(codeProvider);
		if ((codeProvider==CodeProvider.BC || codeProvider==CodeProvider.BCFIPS) && !isXDHType()) {
			return new BCKeyAgreement(type, this);
		}
		else
			return new JavaNativeKeyAgreement(type, KeyAgreement.getInstance(getKeyAgreementAlgorithmName(), getCodeProvider().getCompatibleProvider()));
	}
	
	public boolean isECCDHType()
	{
		return getKeyAgreementAlgorithmName().startsWith("ECCDH");
	}
	
	public boolean isECMQVType()
	{
		return getKeyAgreementAlgorithmName().startsWith("ECMQV");
	}

	public boolean isXDHType()
	{
		return getKeyAgreementAlgorithmName().startsWith("X");
	}

	public boolean isPostQuantumAlgorithm()
	{
		return false;
	}

	public EllipticCurveDiffieHellmanType getDerivedType() {
		return derivedType;
	}
}
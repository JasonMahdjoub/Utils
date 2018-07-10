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

import gnu.vm.jgnu.security.InvalidAlgorithmParameterException;
import gnu.vm.jgnu.security.NoSuchAlgorithmException;
import gnu.vm.jgnu.security.NoSuchProviderException;

/**
 * 
 * @author Jason Mahdjoub
 * @version 1.2
 * @since Utils 3.14.0
 */

public enum KeyAgreementType {
	@Deprecated
	BC_FIPS_ECDDH_384_P_384(false, false, EllipticCurveDiffieHellmanType.BC_FIPS_ECDDH_384_P_384),
	@Deprecated
	BC_FIPS_ECDDH_512_P_521(false, false, EllipticCurveDiffieHellmanType.BC_FIPS_ECDDH_512_P_521), 
	BC_ECCDH_384_CURVE_25519(false, false, EllipticCurveDiffieHellmanType.BC_ECCDH_384_CURVE_25519),
	BC_ECCDH_512_CURVE_25519(false, false, EllipticCurveDiffieHellmanType.BC_ECCDH_512_CURVE_25519), 
	BC_ECCDH_384_CURVE_M_221(false, false, EllipticCurveDiffieHellmanType.BC_ECCDH_384_CURVE_M_221),
	BC_ECCDH_512_CURVE_M_221(false, false, EllipticCurveDiffieHellmanType.BC_ECCDH_512_CURVE_M_221), 
	BC_ECCDH_384_CURVE_M_383(false, false, EllipticCurveDiffieHellmanType.BC_ECCDH_384_CURVE_M_383),
	BC_ECCDH_512_CURVE_M_383(false, false, EllipticCurveDiffieHellmanType.BC_ECCDH_512_CURVE_M_383), 
	BC_ECCDH_384_CURVE_M_511(false, false, EllipticCurveDiffieHellmanType.BC_ECCDH_384_CURVE_M_511),
	BC_ECCDH_512_CURVE_M_511(false, false, EllipticCurveDiffieHellmanType.BC_ECCDH_512_CURVE_M_511), 
	BC_ECCDH_384_CURVE_41417(false, false, EllipticCurveDiffieHellmanType.BC_ECCDH_384_CURVE_41417),
	BC_ECCDH_512_CURVE_41417(false, false, EllipticCurveDiffieHellmanType.BC_ECCDH_512_CURVE_41417),
	/*@Deprecated
	BC_FIPS_ECMQV_384_P_384(false, false, EllipticCurveDiffieHellmanType.BC_FIPS_ECMQV_384_P_384),
	@Deprecated
	BC_FIPS_ECMQV_512_P_512(false, false, EllipticCurveDiffieHellmanType.BC_FIPS_ECMQV_512_P_521), 
	BC_ECMQV_384_CURVE_25519(false, false, EllipticCurveDiffieHellmanType.BC_ECMQV_384_CURVE_25519),
	BC_ECMQV_512_CURVE_25519(false, false, EllipticCurveDiffieHellmanType.BC_ECMQV_512_CURVE_25519), 
	BC_ECMQV_384_CURVE_M_221(false, false, EllipticCurveDiffieHellmanType.BC_ECMQV_384_CURVE_M_221),
	BC_ECMQV_512_CURVE_M_221(false, false, EllipticCurveDiffieHellmanType.BC_ECMQV_512_CURVE_M_221), 
	BC_ECMQV_384_CURVE_M_383(false, false, EllipticCurveDiffieHellmanType.BC_ECMQV_384_CURVE_M_383),
	BC_ECMQV_512_CURVE_M_383(false, false, EllipticCurveDiffieHellmanType.BC_ECMQV_512_CURVE_M_383), 
	BC_ECMQV_384_CURVE_M_511(false, false, EllipticCurveDiffieHellmanType.BC_ECMQV_384_CURVE_M_511),
	BC_ECMQV_512_CURVE_M_511(false, false, EllipticCurveDiffieHellmanType.BC_ECMQV_512_CURVE_M_511), 
	BC_ECMQV_384_CURVE_41417(false, false, EllipticCurveDiffieHellmanType.BC_ECMQV_384_CURVE_41417),
	BC_ECMQV_512_CURVE_41417(false, false, EllipticCurveDiffieHellmanType.BC_ECMQV_512_CURVE_41417),*/
	BCPQC_NEW_HOPE(true, true, null),
	DEFAULT(false, false, EllipticCurveDiffieHellmanType.DEFAULT);
	
	private final boolean isPQC;
	private final boolean isNewHope;
	private final EllipticCurveDiffieHellmanType ecdhType;
	KeyAgreementType(boolean isPQC, boolean isNewHope, EllipticCurveDiffieHellmanType ecdhType) {
		this.isPQC = isPQC;
		this.isNewHope = isNewHope;
		this.ecdhType = ecdhType;
	}
	
	public boolean equals(KeyAgreementType o)
	{
		if (o==null)
			return false;
		
		return o.isNewHope==isNewHope && o.ecdhType.equals(ecdhType);
	}
	public boolean isPostQuantumAlgorithm() {
		return isPQC;
	}
	public KeyAgreement getKeyAgreementClient(AbstractSecureRandom randomForKeys, SymmetricAuthentifiedSignatureType signatureType) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException
	{
		return getKeyAgreementClient(randomForKeys, signatureType, getDefaultKeySizeBits());
	}
	public KeyAgreement getKeyAgreementClient(AbstractSecureRandom randomForKeys, SymmetricAuthentifiedSignatureType signatureType, short keySizeBits) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException
	{
		return getKeyAgreementClient(randomForKeys, signatureType, keySizeBits, null);
	}
	public KeyAgreement getKeyAgreementClient(AbstractSecureRandom randomForKeys, SymmetricAuthentifiedSignatureType signatureType, short keySizeBits, byte[] keyingMaterial) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException
	{
		if (ecdhType!=null)
			return new EllipticCurveDiffieHellmanAlgorithm(randomForKeys, ecdhType, keySizeBits, keyingMaterial, signatureType);
		else if (isNewHope)
		{
			return new NewHopeKeyAgreementClient(signatureType, keySizeBits, randomForKeys);
		}
		else
			throw new InternalError();
			
	}
	public KeyAgreement getKeyAgreementClient(AbstractSecureRandom randomForKeys, SymmetricEncryptionType encryptionType) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException
	{
		
		return getKeyAgreementClient(randomForKeys, encryptionType, getDefaultKeySizeBits());
	}
	public KeyAgreement getKeyAgreementClient(AbstractSecureRandom randomForKeys, SymmetricEncryptionType encryptionType, short keySizeBits) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException
	{
		return getKeyAgreementClient(randomForKeys, encryptionType, keySizeBits, null);
	}
	public KeyAgreement getKeyAgreementClient(AbstractSecureRandom randomForKeys, SymmetricEncryptionType encryptionType, short keySizeBits, byte[] keyingMaterial) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException
	{
		if (ecdhType!=null)
			return new EllipticCurveDiffieHellmanAlgorithm(randomForKeys, ecdhType, keySizeBits, keyingMaterial, encryptionType);
		else if (isNewHope)
		{
			return new NewHopeKeyAgreementClient(encryptionType, keySizeBits, randomForKeys);
		}
		else
			throw new InternalError();
			
	}
	public KeyAgreement getKeyAgreementServer(AbstractSecureRandom randomForKeys, SymmetricAuthentifiedSignatureType signatureType) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException
	{
		return getKeyAgreementServer(randomForKeys, signatureType, getDefaultKeySizeBits());
	}
	public KeyAgreement getKeyAgreementServer(AbstractSecureRandom randomForKeys, SymmetricAuthentifiedSignatureType signatureType, short keySizeBits) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException
	{
		return getKeyAgreementServer(randomForKeys, signatureType, keySizeBits, null);
	}
	public KeyAgreement getKeyAgreementServer(AbstractSecureRandom randomForKeys, SymmetricAuthentifiedSignatureType signatureType, short keySizeBits, byte[] keyingMaterial) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException
	{
		if (ecdhType!=null)
			return new EllipticCurveDiffieHellmanAlgorithm(randomForKeys, ecdhType, keySizeBits, keyingMaterial, signatureType);
		else if (isNewHope)
		{
			return new NewHopeKeyAgreementServer(signatureType, keySizeBits, randomForKeys);
		}
		else
			throw new InternalError();
			
	}
	public KeyAgreement getKeyAgreementServer(AbstractSecureRandom randomForKeys, SymmetricEncryptionType encryptionType) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException
	{
		return getKeyAgreementServer(randomForKeys, encryptionType, getDefaultKeySizeBits());
	}
	public KeyAgreement getKeyAgreementServer(AbstractSecureRandom randomForKeys, SymmetricEncryptionType encryptionType, short keySizeBits) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException
	{
		return getKeyAgreementServer(randomForKeys, encryptionType, keySizeBits, null);
	}
	public KeyAgreement getKeyAgreementServer(AbstractSecureRandom randomForKeys, SymmetricEncryptionType encryptionType, short keySizeBits, byte[] keyingMaterial) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException
	{
		if (ecdhType!=null)
			return new EllipticCurveDiffieHellmanAlgorithm(randomForKeys, ecdhType, keySizeBits, keyingMaterial, encryptionType);
		else if (isNewHope)
		{
			return new NewHopeKeyAgreementServer(encryptionType, keySizeBits, randomForKeys);
		}
		else
			throw new InternalError();
			
	}
	
	
	public short getDefaultKeySizeBits()
	{
		if (ecdhType==null)
			return 256;
		else
			return ecdhType.getKeySizeBits();
	}
	
	public CodeProvider getCodeProvider()
	{
		if (ecdhType==null)
			return CodeProvider.BCPQC;
		else
			return ecdhType.getCodeProvider();
	}
	
	
}

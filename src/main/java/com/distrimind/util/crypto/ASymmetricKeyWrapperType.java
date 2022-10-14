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
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.MGF1ParameterSpec;
import java.util.Arrays;
import java.util.Random;

import javax.crypto.*;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

import com.distrimind.util.OSVersion;
import com.distrimind.util.data_buffers.WrappedData;
import com.distrimind.util.data_buffers.WrappedSecretData;
import com.distrimind.util.io.Integrity;
import com.distrimind.util.io.MessageExternalizationException;
import com.distrimind.bcfips.crypto.InvalidWrappingException;
import com.distrimind.bcfips.crypto.KeyUnwrapperUsingSecureRandom;
import com.distrimind.bcfips.crypto.KeyWrapperUsingSecureRandom;
import com.distrimind.bcfips.crypto.asymmetric.AsymmetricRSAPrivateKey;
import com.distrimind.bcfips.crypto.asymmetric.AsymmetricRSAPublicKey;
import com.distrimind.bcfips.crypto.fips.FipsDigestAlgorithm;
import com.distrimind.bcfips.crypto.fips.FipsRSA;
import com.distrimind.bcfips.crypto.fips.FipsSHS;
import com.distrimind.bcfips.crypto.fips.FipsRSA.OAEPParameters;
import com.distrimind.bcfips.crypto.fips.FipsRSA.WrapParameters;

import com.distrimind.util.Bits;
import com.distrimind.util.OS;


/**
 * 
 * @author Jason Mahdjoub
 * @version 3.2
 * @since Utils 1.17.0
 */
@SuppressWarnings({"ConstantConditions", "DeprecatedIsStillUsed"})
public enum ASymmetricKeyWrapperType {

	RSA_OAEP_WITH_SHA2_384("RSA/ECB/OAEPPadding",CodeProvider.SunJCE, false, "SHA-384", FipsSHS.Algorithm.SHA384, false, ASymmetricEncryptionType.RSA_OAEPWithSHA384AndMGF1Padding),
	RSA_OAEP_WITH_PARAMETERS_SHA2_384("RSA/ECB/OAEPPadding",CodeProvider.SunJCE, true, "SHA-384", FipsSHS.Algorithm.SHA384, false, ASymmetricEncryptionType.RSA_OAEPWithSHA384AndMGF1Padding),
	@Deprecated
	GNU_RSA_OAEP_SHA2_384("RSA/NONE/OAEPPadding",CodeProvider.GNU_CRYPTO, false, "SHA-384", FipsSHS.Algorithm.SHA384, false, ASymmetricEncryptionType.RSA_OAEPWithSHA384AndMGF1Padding),
	RSA_OAEP_SHA2_512("RSA/ECB/OAEPPadding",CodeProvider.SunJCE, false, "SHA-512", FipsSHS.Algorithm.SHA512, false, ASymmetricEncryptionType.RSA_OAEPWithSHA512AndMGF1Padding),
	RSA_OAEP_WITH_PARAMETERS_SHA2_512("RSA/ECB/OAEPPadding",CodeProvider.SunJCE, true, "SHA-512", FipsSHS.Algorithm.SHA512, false, ASymmetricEncryptionType.RSA_OAEPWithSHA512AndMGF1Padding),
	GNU_RSA_OAEP_SHA2_512("RSA/NONE/OAEPPadding",CodeProvider.GNU_CRYPTO, false, "SHA-512", FipsSHS.Algorithm.SHA512, false, ASymmetricEncryptionType.RSA_OAEPWithSHA512AndMGF1Padding),
	BC_FIPS_RSA_OAEP_WITH_SHA2_384("RSA/NONE/OAEPPadding",CodeProvider.BCFIPS, false, "SHA-384", FipsSHS.Algorithm.SHA384, false, ASymmetricEncryptionType.RSA_OAEPWithSHA384AndMGF1Padding),
	BC_FIPS_RSA_OAEP_WITH_PARAMETERS_SHA2_384("RSA/NONE/OAEPPadding",CodeProvider.BCFIPS, true, "SHA-384", FipsSHS.Algorithm.SHA384, false, ASymmetricEncryptionType.RSA_OAEPWithSHA384AndMGF1Padding),
	BC_FIPS_RSA_OAEP_WITH_SHA2_512("RSA/NONE/OAEPPadding",CodeProvider.BCFIPS, false, "SHA-384", FipsSHS.Algorithm.SHA512, false, ASymmetricEncryptionType.RSA_OAEPWithSHA512AndMGF1Padding),
	BC_FIPS_RSA_OAEP_WITH_PARAMETERS_SHA2_512("RSA/NONE/OAEPPadding",CodeProvider.BCFIPS, true, "SHA-384", FipsSHS.Algorithm.SHA512, false, ASymmetricEncryptionType.RSA_OAEPWithSHA512AndMGF1Padding),
	BC_FIPS_RSA_OAEP_WITH_SHA3_384("RSA/NONE/OAEPPadding",CodeProvider.BCFIPS, false, "SHA-384", FipsSHS.Algorithm.SHA3_384, false, ASymmetricEncryptionType.RSA_OAEPWithSHA384AndMGF1Padding),
	BC_FIPS_RSA_OAEP_WITH_PARAMETERS_SHA3_384("RSA/NONE/OAEPPadding",CodeProvider.BCFIPS, true, "SHA-384", FipsSHS.Algorithm.SHA3_384, false, ASymmetricEncryptionType.RSA_OAEPWithSHA384AndMGF1Padding),
	BC_FIPS_RSA_OAEP_WITH_SHA3_512("RSA/NONE/OAEPPadding",CodeProvider.BCFIPS, false, "SHA-384", FipsSHS.Algorithm.SHA3_512, false, ASymmetricEncryptionType.RSA_OAEPWithSHA512AndMGF1Padding),
	BC_FIPS_RSA_OAEP_WITH_PARAMETERS_SHA3_512("RSA/NONE/OAEPPadding",CodeProvider.BCFIPS, true, "SHA-384", FipsSHS.Algorithm.SHA3_512, false, ASymmetricEncryptionType.RSA_OAEPWithSHA512AndMGF1Padding),
	BCPQC_MCELIECE_FUJISAKI_CCA2_SHA256("McElieceFujisaki",CodeProvider.BCPQC, false, "SHA-256", FipsSHS.Algorithm.SHA256, true, ASymmetricEncryptionType.BCPQC_MCELIECE_FUJISAKI_CCA2_SHA256),
	BCPQC_MCELIECE_POINTCHEVAL_CCA2_SHA256("McEliecePointCheval",CodeProvider.BCPQC, false, "SHA-256", FipsSHS.Algorithm.SHA256, true, ASymmetricEncryptionType.BCPQC_MCELIECE_POINTCHEVAL_CCA2_SHA256),
	HYBRID_BCPQC_MCELIECE_FUJISAKI_CCA2_SHA256_AND_RSA_OAEP_WITH_SHA2_384(BCPQC_MCELIECE_FUJISAKI_CCA2_SHA256, RSA_OAEP_WITH_SHA2_384),
	HYBRID_BCPQC_MCELIECE_FUJISAKI_CCA2_SHA256_AND_RSA_OAEP_WITH_PARAMETERS_SHA2_384(BCPQC_MCELIECE_FUJISAKI_CCA2_SHA256, RSA_OAEP_WITH_PARAMETERS_SHA2_384),
	HYBRID_BCPQC_MCELIECE_POINTCHEVAL_CCA2_SHA256_AND_RSA_OAEP_WITH_SHA2_384(BCPQC_MCELIECE_POINTCHEVAL_CCA2_SHA256, RSA_OAEP_WITH_SHA2_384),
	HYBRID_BCPQC_MCELIECE_POINTCHEVAL_CCA2_SHA256_AND_RSA_OAEP_WITH_PARAMETERS_SHA2_384(BCPQC_MCELIECE_POINTCHEVAL_CCA2_SHA256, RSA_OAEP_WITH_PARAMETERS_SHA2_384),
	BCPQC_CRYSTALS_KYBER_512("Kyber",CodeProvider.BCPQC, false, "512", null, true, ASymmetricEncryptionType.BCPQC_CRYSTALS_KYBER_512),
	BCPQC_CRYSTALS_KYBER_768("Kyber",CodeProvider.BCPQC, false, "768", null, true, ASymmetricEncryptionType.BCPQC_CRYSTALS_KYBER_768),
	BCPQC_CRYSTALS_KYBER_1024("Kyber",CodeProvider.BCPQC, false, "1024", null, true, ASymmetricEncryptionType.BCPQC_CRYSTALS_KYBER_1024),
	BCPQC_CRYSTALS_KYBER_512_AES("Kyber",CodeProvider.BCPQC, false, "512_AES", null, true, ASymmetricEncryptionType.BCPQC_CRYSTALS_KYBER_512_AES),
	BCPQC_CRYSTALS_KYBER_768_AES("Kyber",CodeProvider.BCPQC, false, "768_AES", null, true, ASymmetricEncryptionType.BCPQC_CRYSTALS_KYBER_768_AES),
	BCPQC_CRYSTALS_KYBER_1024_AES("Kyber",CodeProvider.BCPQC, false, "1024_AES", null, true, ASymmetricEncryptionType.BCPQC_CRYSTALS_KYBER_1024_AES),
	HYBRID_BCPQC_BCPQC_CRYSTALS_KYBER_512_AND_BC_FIPS_RSA_OAEP_WITH_SHA3_512(BCPQC_CRYSTALS_KYBER_512, BC_FIPS_RSA_OAEP_WITH_SHA3_512),
	HYBRID_BCPQC_BCPQC_CRYSTALS_KYBER_768_AND_BC_FIPS_RSA_OAEP_WITH_SHA3_512(BCPQC_CRYSTALS_KYBER_768, BC_FIPS_RSA_OAEP_WITH_SHA3_512),
	HYBRID_BCPQC_BCPQC_CRYSTALS_KYBER_1024_AND_BC_FIPS_RSA_OAEP_WITH_SHA3_512(BCPQC_CRYSTALS_KYBER_1024, BC_FIPS_RSA_OAEP_WITH_SHA3_512),
	HYBRID_BCPQC_BCPQC_CRYSTALS_KYBER_512_AES_AND_BC_FIPS_RSA_OAEP_WITH_SHA3_512(BCPQC_CRYSTALS_KYBER_512_AES, BC_FIPS_RSA_OAEP_WITH_SHA3_512),
	HYBRID_BCPQC_BCPQC_CRYSTALS_KYBER_768_AES_AND_BC_FIPS_RSA_OAEP_WITH_SHA3_512(BCPQC_CRYSTALS_KYBER_768_AES, BC_FIPS_RSA_OAEP_WITH_SHA3_512),
	HYBRID_BCPQC_BCPQC_CRYSTALS_KYBER_1024_AES_AND_BC_FIPS_RSA_OAEP_WITH_SHA3_512(BCPQC_CRYSTALS_KYBER_1024_AES, BC_FIPS_RSA_OAEP_WITH_SHA3_512),
	//BC_FIPS_RSA_KTS_KTM("RSA-KTS-KEM-KWS",CodeProvider.BCFIPS, false),
	DEFAULT(BC_FIPS_RSA_OAEP_WITH_PARAMETERS_SHA3_384);
	
	
	
	private final String algorithmName;
	private final CodeProvider provider;
	private final boolean withParameters;
	private final String shaAlgorithm;
	private final FipsDigestAlgorithm bcShaDigestAlgorithm;
	private final boolean pqc;

	private final ASymmetricEncryptionType aSymmetricEncryptionType;
	private final ASymmetricKeyWrapperType nonPQCWrapper, pqcWrapper;
	private final ASymmetricKeyWrapperType derivedType;

	public boolean equals(ASymmetricKeyWrapperType type)
	{
		if (type==null)
			return false;
		//noinspection StringEquality
		return type.algorithmName==this.algorithmName && type.provider==this.provider && type.shaAlgorithm==this.shaAlgorithm;
	}
	ASymmetricKeyWrapperType(ASymmetricKeyWrapperType pqcWrapper, ASymmetricKeyWrapperType nonPQCWrapper) {
		this.algorithmName = "";
		this.provider = null;
		this.withParameters=false;
		this.shaAlgorithm="";
		this.bcShaDigestAlgorithm=null;
		this.pqc=true;
		this.aSymmetricEncryptionType=null;
		this.nonPQCWrapper=nonPQCWrapper.derivedType;
		this.pqcWrapper=pqcWrapper.derivedType;
		this.derivedType= this;
	}

	ASymmetricKeyWrapperType(String algorithmName, CodeProvider provider, boolean withParameters, String shaAlgorithm, FipsDigestAlgorithm bcShaDigestAlgorithm, boolean pqc, ASymmetricEncryptionType aSymmetricEncryptionType) {
		if (aSymmetricEncryptionType==null)
			throw new NullPointerException();
		this.algorithmName = algorithmName;
		this.provider = provider;
		this.withParameters=withParameters;
		this.shaAlgorithm=shaAlgorithm;
		this.bcShaDigestAlgorithm=bcShaDigestAlgorithm;
		this.pqc=pqc;
		this.aSymmetricEncryptionType=aSymmetricEncryptionType;
		this.nonPQCWrapper=null;
		this.pqcWrapper=null;
		this.derivedType=this;
	}
	
	ASymmetricKeyWrapperType(ASymmetricKeyWrapperType other)
	{
		this.algorithmName = other.algorithmName;
		this.provider = other.provider;
		this.withParameters=other.withParameters;
		this.shaAlgorithm=other.shaAlgorithm;
		this.bcShaDigestAlgorithm=other.bcShaDigestAlgorithm;
		this.pqc=other.pqc;
		this.aSymmetricEncryptionType=other.aSymmetricEncryptionType;
		this.nonPQCWrapper=other.nonPQCWrapper;
		this.pqcWrapper=other.pqcWrapper;
		this.derivedType=other;
	}
	public boolean isHybrid()
	{
		return nonPQCWrapper!=null && pqcWrapper!=null;
	}
	public CodeProvider getCodeProvider()
	{
		return provider;
	}
	public String getAlgorithmName()
	{
		return algorithmName;
	}

	public ASymmetricKeyWrapperType getNonPQCWrapper() {
		return nonPQCWrapper;
	}

	public ASymmetricKeyWrapperType getPqcWrapper() {
		return pqcWrapper;
	}

	static byte[] wrapKeyWithMetaData(byte[] wrappedKey, SymmetricSecretKey keyToWrap)
	{
		byte[] res=new byte[wrappedKey.length+2+SymmetricSecretKey.ENCODED_TYPE_SIZE];
		res[0]=keyToWrap.useAuthenticatedSignatureAlgorithm()?(byte)1:(byte)0;
		Bits.putUnsignedInt(res, 1, keyToWrap.getAuthenticatedSignatureAlgorithmType()!=null?keyToWrap.getAuthenticatedSignatureAlgorithmType().ordinal():keyToWrap.getEncryptionAlgorithmType().ordinal(), SymmetricSecretKey.ENCODED_TYPE_SIZE);
		res[1+SymmetricSecretKey.ENCODED_TYPE_SIZE]=(byte)SymmetricSecretKey.encodeKeySizeBits(keyToWrap.getKeySizeBits());
		System.arraycopy(wrappedKey, 0, res, 2+SymmetricSecretKey.ENCODED_TYPE_SIZE, wrappedKey.length);
		return res;
	}
	static byte[] getWrappedKeyFromMetaData(WrappedSecretData wrappedSecretData) throws InvalidKeyException
	{
		byte[] wk= wrappedSecretData.getBytes();
		if (wk.length<9)
			throw new InvalidKeyException();
		byte[] res=new byte[wk.length-2-SymmetricSecretKey.ENCODED_TYPE_SIZE];
		System.arraycopy(wk, 2+SymmetricSecretKey.ENCODED_TYPE_SIZE, res, 0, res.length);
		return res;
	}
	static boolean isSignatureFromMetaData(WrappedSecretData wrappedSecretData) throws InvalidKeyException
	{
		byte[] wk= wrappedSecretData.getBytes();
		if (wk.length<9)
			throw new InvalidKeyException();
		return wk[0]==1;
	}
	static short getKeySizeFromMetaData(WrappedSecretData wrappedSecretData) throws InvalidKeyException
	{
		byte[] wk= wrappedSecretData.getBytes();
		if (wk.length<9)
			throw new InvalidKeyException();
		return SymmetricSecretKey.decodeKeySizeBits(wk[1+SymmetricSecretKey.ENCODED_TYPE_SIZE]);
	}
	
	static SymmetricAuthenticatedSignatureType getSignatureTypeFromMetaData(WrappedSecretData wrappedSecretData) throws InvalidKeyException
	{
		byte[] wk= wrappedSecretData.getBytes();
		if (wk.length<9)
			throw new InvalidKeyException();
		int ordinal=(int)Bits.getUnsignedInt(wk, 1, SymmetricSecretKey.ENCODED_TYPE_SIZE);
		for (SymmetricAuthenticatedSignatureType t : SymmetricAuthenticatedSignatureType.values())
		{
			if (t.ordinal()==ordinal)
				return t;
		}
		throw new InvalidKeyException();
	}
	static SymmetricEncryptionType getEncryptionTypeFromMetaData(WrappedSecretData wrappedSecretData) throws InvalidKeyException
	{
		byte[] wk= wrappedSecretData.getBytes();
		if (wk.length<9)
			throw new InvalidKeyException();
		int ordinal=(int)Bits.getUnsignedInt(wk, 1, SymmetricSecretKey.ENCODED_TYPE_SIZE);
		for (SymmetricEncryptionType t : SymmetricEncryptionType.values())
		{
			if (t.ordinal()==ordinal)
				return t;
		}
		throw new InvalidKeyException(""+ordinal);
	}
	
	private OAEPParameters getOAEPParams(byte[] params)
	{
		OAEPParameters OAEPParams=FipsRSA.WRAP_OAEP;
		if (withParameters)
			OAEPParams=OAEPParams.withMGFDigest(bcShaDigestAlgorithm)
						.withEncodingParams(params);
		return OAEPParams;
	}

	WrappedEncryptedSymmetricSecretKey wrapKey(AbstractSecureRandom random, IASymmetricPublicKey ipublicKey, SymmetricSecretKey keyToWrap)
			throws IOException {
		if (ipublicKey.isDestroyed())
			throw new IllegalArgumentException();
		if (keyToWrap.isCleaned())
			throw new IllegalArgumentException();
		try {
			if (ipublicKey instanceof ASymmetricPublicKey) {
				if (isHybrid())
					throw new IllegalArgumentException();
				ASymmetricPublicKey publicKey = (ASymmetricPublicKey) ipublicKey;
				if (publicKey.getAuthenticatedSignatureAlgorithmType() != null)
					throw new IllegalArgumentException();
				//CodeProvider.ensureProviderLoaded(provider);
				if (name().startsWith("BCPQC_MCELIECE_")) {
					if (!publicKey.getEncryptionAlgorithmType().name().equals(name()))
						throw new IllegalArgumentException(publicKey.getEncryptionAlgorithmType().toString()+" ; "+name());
					try(ClientASymmetricEncryptionAlgorithm client = new ClientASymmetricEncryptionAlgorithm(random, publicKey)) {
						WrappedSecretData wsd = keyToWrap.encode();
						return new WrappedEncryptedSymmetricSecretKey(client.encode(wsd.getBytes()));
					}
				} else {
					if ( (publicKey.getEncryptionAlgorithmType() != null && ((provider == CodeProvider.GNU_CRYPTO) != (publicKey.getEncryptionAlgorithmType().getCodeProviderForEncryption() == CodeProvider.GNU_CRYPTO)))
							|| (keyToWrap.getAuthenticatedSignatureAlgorithmType() != null && (provider == CodeProvider.GNU_CRYPTO) != (keyToWrap.getAuthenticatedSignatureAlgorithmType().getCodeProviderForSignature() == CodeProvider.GNU_CRYPTO))
							|| (keyToWrap.getEncryptionAlgorithmType() != null && (provider == CodeProvider.GNU_CRYPTO) != (keyToWrap.getEncryptionAlgorithmType().getCodeProviderForEncryption() == CodeProvider.GNU_CRYPTO)))
						throw new IllegalArgumentException("The keys must come from the same providers");

					if ((algorithmName.equals(BCPQC_CRYSTALS_KYBER_512.algorithmName) && !publicKey.getEncryptionAlgorithmType().getAlgorithmName().contains(algorithmName))
							|| (!algorithmName.equals(BCPQC_CRYSTALS_KYBER_512.algorithmName) && !algorithmName.contains(publicKey.getEncryptionAlgorithmType().getAlgorithmName())))
						throw new IllegalArgumentException("The key must be compatible with algorithm " + algorithmName+", publicKeyEncryptionAlgorithmType="+publicKey.getEncryptionAlgorithmType());
					if (provider.equals(CodeProvider.GNU_CRYPTO)) {
						Object c = GnuFunctions.getCipherAlgorithm(algorithmName);
						GnuFunctions.cipherInitWrapMode(c, publicKey.toGnuKey(), random.getGnuSecureRandom());
						byte[] t=GnuFunctions.cipherWrap(c, keyToWrap.toGnuKey());
						byte[] res=wrapKeyWithMetaData(t, keyToWrap);
						Arrays.fill(t, (byte)0);
						return new WrappedEncryptedSymmetricSecretKey(res);
					} else {
						javax.crypto.Cipher c;
						if (provider.equals(CodeProvider.BCFIPS) || (OSVersion.getCurrentOSVersion() != null && OSVersion.getCurrentOSVersion().getOS() == OS.MAC_OS_X && (this.getCodeProvider() == CodeProvider.SunJCE))) {


							AsymmetricRSAPublicKey bcPK = (AsymmetricRSAPublicKey) publicKey.toBouncyCastleKey();

							WrappedData encodedKey = keyToWrap.encode();

							OAEPParameters OAEPParams = getOAEPParams(PSource.PSpecified.DEFAULT.getValue());

			/*if (this.algorithmName.equals(BC_FIPS_RSA_KTS_KTM.algorithmName))
			{
				OAEPKTSParameters OAEPKTSParams=FipsRSA.KTS_OAEP
						.withOAEPParameters(OAEPParams)
						.withKeySizeInBits(256)
						.withMacKeySizeInBits(256);

				FipsRSA.KTSOperatorFactory wrapFact=new FipsRSA.KTSOperatorFactory(random);
				wrapFact.createGenerator
				FipsEncapsulatingSecretGenerator<FipsRSA.KTSParameters> wrapper=wrapFact.createGenerator(bcPK, OAEPKTSParams)
						.withSecureRandom(random);


			}
			else
			{*/
							FipsRSA.KeyWrapOperatorFactory wrapFact = new FipsRSA.KeyWrapOperatorFactory();
							KeyWrapperUsingSecureRandom<FipsRSA.WrapParameters> wrapper =
									wrapFact.createKeyWrapper(bcPK, OAEPParams)
											.withSecureRandom(random);


							byte[] wrapedKey = wrapper.wrap(encodedKey.getBytes(), 0, encodedKey.getBytes().length);
							byte[] res;
							if (withParameters) {
								byte[] encodedParameters = OAEPParams.getEncodingParams();
								byte[] concat=Bits.concatenateEncodingWithShortSizedTabs(wrapedKey, encodedParameters);
								res= wrapKeyWithMetaData(concat, keyToWrap);
								Arrays.fill(concat, (byte)0);
							} else
								res=wrapKeyWithMetaData(wrapedKey, keyToWrap);
							Arrays.fill(wrapedKey, (byte)0);
							return new WrappedEncryptedSymmetricSecretKey(res);

						}
		/*if (OSValidator.getCurrentOS()==OSValidator.MACOS && (this==RSA_OAEP || this==ASymmetricKeyWrapperType.RSA_OAEP_WITH_PARAMETERS))
		{
			CodeProvider.ensureBouncyCastleProviderLoaded();

			c=javax.crypto.Cipher.getInstance(algorithmName, CodeProvider.BCFIPS.getCompatibleProviderName());
		}*/
						else
							c = javax.crypto.Cipher.getInstance(algorithmName, provider.getCompatibleProvider());

						if (withParameters) {
							c.init(javax.crypto.Cipher.WRAP_MODE, publicKey.toJavaNativeKey(),
									new OAEPParameterSpec(shaAlgorithm, "MGF1", new MGF1ParameterSpec(shaAlgorithm), PSource.PSpecified.DEFAULT), random);
							byte[] wrapedKey = c.wrap(keyToWrap.toJavaNativeKey());
							byte[] encodedParameters = c.getParameters().getEncoded();
							byte[] concat=Bits.concatenateEncodingWithShortSizedTabs(wrapedKey, encodedParameters);
							byte[] res=wrapKeyWithMetaData(concat, keyToWrap);
							Arrays.fill(concat, (byte)0);
							Arrays.fill(wrapedKey, (byte)0);
							return new WrappedEncryptedSymmetricSecretKey(res);
						}
		/*else if (this.algorithmName.equals(BC_FIPS_RSA_KTS_KTM.algorithmName))
		{
			c.init(javax.crypto.Cipher.WRAP_MODE, publicKey.toJavaNativeKey(), new KTSParameterSpec.Builder(NISTObjectIdentifiers.id_aes256_wrap.getId(),256).build(), random);
			return wrapKeyWithMetaData(c.wrap(keyToWrap.toJavaNativeKey()), keyToWrap);
		}*/
						else {
							c.init(javax.crypto.Cipher.WRAP_MODE, publicKey.toJavaNativeKey(), random);
							byte[] wrappedKey=c.wrap(keyToWrap.toJavaNativeKey());
							byte[] res=wrapKeyWithMetaData(wrappedKey, keyToWrap);
							Arrays.fill(wrappedKey, (byte)0);
							return new WrappedEncryptedSymmetricSecretKey(res);
						}
					}
				}
			} else {
				if (!isHybrid())
					throw new IllegalArgumentException(""+ipublicKey.getClass().getName());

				HybridASymmetricPublicKey publicKey = (HybridASymmetricPublicKey) ipublicKey;
				if (!publicKey.getPQCPublicKey().getEncryptionAlgorithmType().name().equals(getPqcWrapper().name()))
					throw new IllegalArgumentException(publicKey.getPQCPublicKey().getEncryptionAlgorithmType()+" ; "+getPqcWrapper().name());
				WrappedEncryptedSymmetricSecretKey nonPQCWrap = nonPQCWrapper.wrapKey(random, publicKey.getNonPQCPublicKey(), keyToWrap);
				try(ClientASymmetricEncryptionAlgorithm client = new ClientASymmetricEncryptionAlgorithm(random, publicKey.getPQCPublicKey()))
				{
					return new WrappedEncryptedSymmetricSecretKey(client.encode(nonPQCWrap.getBytes()));
				}
			}
		} catch (InvalidKeySpecException | NoSuchAlgorithmException | NoSuchProviderException | InvalidKeyException | InvalidAlgorithmParameterException | NoSuchPaddingException | IllegalBlockSizeException e) {
			throw new IOException(e);
		}

	}
	
	SymmetricSecretKey unwrapKey(IASymmetricPrivateKey iPrivateKey, WrappedEncryptedSymmetricSecretKey keyToUnwrap) throws IOException
	{
		if (keyToUnwrap.isCleaned())
			throw new IllegalArgumentException();
		if (iPrivateKey.isCleaned())
			throw new IllegalArgumentException();
		try {
			if (iPrivateKey instanceof ASymmetricPrivateKey)
			{
				if (isHybrid())
					throw new IllegalArgumentException();
				ASymmetricPrivateKey privateKey = (ASymmetricPrivateKey) iPrivateKey;
				if (name().startsWith("BCPQC_MCELIECE_")) {

					if (!privateKey.getEncryptionAlgorithmType().name().equals(name()))
						throw new IllegalArgumentException();
					ServerASymmetricEncryptionAlgorithm server = new ServerASymmetricEncryptionAlgorithm(privateKey);
					AbstractKey res = AbstractKey.decode(server.decode(keyToUnwrap.getBytes()));
					if (res instanceof SymmetricSecretKey)
						return (SymmetricSecretKey) res;
					else
						throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN);
				} else {
					if ((algorithmName.equals(BCPQC_CRYSTALS_KYBER_512.algorithmName) && !privateKey.getEncryptionAlgorithmType().getAlgorithmName().contains(algorithmName))
							|| (!algorithmName.equals(BCPQC_CRYSTALS_KYBER_512.algorithmName) && !algorithmName.contains(privateKey.getEncryptionAlgorithmType().getAlgorithmName())))
						throw new IllegalArgumentException("The key must be compatible with algorithm " + algorithmName+", privateKeyEncryptionAlgorithmType="+privateKey.getEncryptionAlgorithmType());
					if (isSignatureFromMetaData(keyToUnwrap)) {
						byte[] ktu = getWrappedKeyFromMetaData(keyToUnwrap);
						SymmetricSecretKey res = unwrapKey(privateKey, ktu, null, getSignatureTypeFromMetaData(keyToUnwrap), getKeySizeFromMetaData(keyToUnwrap));
						Arrays.fill(ktu, (byte) 0);
						return res;
					} else {
						byte[] ktu = getWrappedKeyFromMetaData(keyToUnwrap);
						SymmetricSecretKey res = unwrapKey(privateKey, ktu, getEncryptionTypeFromMetaData(keyToUnwrap), null, getKeySizeFromMetaData(keyToUnwrap));
						Arrays.fill(ktu, (byte) 0);
						return res;
					}
				}
			}
			else {
				if (!isHybrid())
					throw new IllegalArgumentException();
				HybridASymmetricPrivateKey privateKey = (HybridASymmetricPrivateKey) iPrivateKey;
				if (!privateKey.getPQCPrivateKey().getEncryptionAlgorithmType().name().equals(getPqcWrapper().name()))
					throw new IllegalArgumentException();
				ServerASymmetricEncryptionAlgorithm server = new ServerASymmetricEncryptionAlgorithm(privateKey.getPQCPrivateKey());
				byte[] b = server.decode(keyToUnwrap.getBytes());
				return getNonPQCWrapper().unwrapKey(privateKey.getNonPQCPrivateKey(), new WrappedEncryptedSymmetricSecretKey(b));
			}
		} catch (InvalidKeyException e) {
			throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN, e);
		}
	}
	private SymmetricSecretKey unwrapKey(ASymmetricPrivateKey privateKey, byte[] keyToUnwrap, SymmetricEncryptionType encryptionType, SymmetricAuthenticatedSignatureType signatureType, short keySize) throws IOException
	{
		if (privateKey.isCleaned())
			throw new IllegalArgumentException();

		try {
			//CodeProvider.ensureProviderLoaded(getCodeProvider());
			if ((privateKey.getAuthenticatedSignatureAlgorithmType() != null && ((provider == CodeProvider.GNU_CRYPTO) != (privateKey.getAuthenticatedSignatureAlgorithmType().getCodeProviderForSignature() == CodeProvider.GNU_CRYPTO)))
					|| (privateKey.getEncryptionAlgorithmType() != null && ((provider == CodeProvider.GNU_CRYPTO) != (privateKey.getEncryptionAlgorithmType().getCodeProviderForEncryption() == CodeProvider.GNU_CRYPTO)))
					|| (encryptionType != null && (provider == CodeProvider.GNU_CRYPTO) != (encryptionType.getCodeProviderForEncryption() == CodeProvider.GNU_CRYPTO))
					|| (signatureType != null && (provider == CodeProvider.GNU_CRYPTO) != (signatureType.getCodeProviderForSignature() == CodeProvider.GNU_CRYPTO)))
				throw new IllegalArgumentException("The keys must come from the same providers");
			if (provider.equals(CodeProvider.GNU_CRYPTO)) {
				Object c = GnuFunctions.getCipherAlgorithm(algorithmName);
				GnuFunctions.cipherInitUnwrapMode(c, privateKey.toGnuKey());
				if (encryptionType == null) {

					return new SymmetricSecretKey(signatureType, GnuFunctions.cipherUnwrap(c, keyToUnwrap, signatureType.getAlgorithmName()), keySize);
				} else {

					return new SymmetricSecretKey(encryptionType, GnuFunctions.cipherUnwrap(c, keyToUnwrap, encryptionType.getAlgorithmName()), keySize);
				}

			} else {

				javax.crypto.Cipher c;
				if (provider.equals(CodeProvider.BCFIPS) || (OSVersion.getCurrentOSVersion() != null && OSVersion.getCurrentOSVersion().getOS() == OS.MAC_OS_X && (this.getCodeProvider() == CodeProvider.SunJCE))) {

					AsymmetricRSAPrivateKey bcPK = (AsymmetricRSAPrivateKey) privateKey.toBouncyCastleKey();

					OAEPParameters OAEPParams;

					byte[] wrappedKey;
					if (withParameters) {
						byte[][] tmp = Bits.separateEncodingsWithShortSizedTabs(keyToUnwrap);
						wrappedKey = tmp[0];
						OAEPParams = getOAEPParams(tmp[1]);
					} else {
						wrappedKey = keyToUnwrap;
						OAEPParams = getOAEPParams(null);
					}


					FipsRSA.KeyWrapOperatorFactory wrapFact = new FipsRSA.KeyWrapOperatorFactory();
					KeyUnwrapperUsingSecureRandom<WrapParameters> unWrapper =
							wrapFact.createKeyUnwrapper(bcPK, OAEPParams)
									.withSecureRandom(SecureRandomType.DEFAULT.getSingleton(null));

					return (SymmetricSecretKey) AbstractKey.decode(unWrapper.unwrap(wrappedKey, 0, wrappedKey.length));

				}
/*if (OSValidator.getCurrentOS()==OSValidator.MACOS && (this==RSA_OAEP || this==ASymmetricKeyWrapperType.RSA_OAEP_WITH_PARAMETERS))
{
	CodeProvider.ensureBouncyCastleProviderLoaded();

	c=javax.crypto.Cipher.getInstance(algorithmName, CodeProvider.BCFIPS.getCompatibleProviderName());
}*/
				else
					c = javax.crypto.Cipher.getInstance(algorithmName, provider.getCompatibleProvider());

				byte[] wrappedKey;
				if (withParameters) {
					byte[][] tmp = Bits.separateEncodingsWithShortSizedTabs(keyToUnwrap);
					wrappedKey = tmp[0];
					AlgorithmParameters algorithmParameters = AlgorithmParameters.getInstance("OAEP");
					algorithmParameters.init(tmp[1]);
					c.init(Cipher.UNWRAP_MODE, privateKey.toJavaNativeKey(), algorithmParameters);
				}
/*else if (this.algorithmName.equals(BC_FIPS_RSA_KTS_KTM.algorithmName))
{
	wrappedKey=keyToUnwrap;
	c.init(Cipher.UNWRAP_MODE, privateKey.toJavaNativeKey(), new KTSParameterSpec.Builder(NISTObjectIdentifiers.id_aes256_wrap.getId(),256).build());
}*/
				else {
					wrappedKey = keyToUnwrap;
					c.init(Cipher.UNWRAP_MODE, privateKey.toJavaNativeKey());
				}
				if (encryptionType == null) {
					return new SymmetricSecretKey(signatureType, (javax.crypto.SecretKey) c.unwrap(wrappedKey, signatureType.getAlgorithmName(), javax.crypto.Cipher.SECRET_KEY), keySize);
				} else {
					return new SymmetricSecretKey(encryptionType, (javax.crypto.SecretKey) c.unwrap(wrappedKey, encryptionType.getAlgorithmName(), javax.crypto.Cipher.SECRET_KEY), keySize);
				}


			}
		}
		catch (NoSuchAlgorithmException | NoSuchProviderException e) {
			throw new MessageExternalizationException(Integrity.FAIL, e);
		} catch (InvalidWrappingException | InvalidKeySpecException | InvalidAlgorithmParameterException | NoSuchPaddingException | InvalidKeyException e) {
			throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN, e);
		}
	}


	public boolean isPostQuantumKeyAlgorithm()
	{
		return pqc;
	}

	boolean wrappingIncludeSignature()
	{
		return getCodeProvider()!=CodeProvider.BCPQC;
	}

	public static int getOutputSizeAfterEncryption(ASymmetricPublicKey publicKey, ASymmetricKeyWrapperType type, int size) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
		if (publicKey.isDestroyed())
			throw new IllegalArgumentException();
		WrappedData encodedKey = new WrappedData(new byte[size]);
		Random r=new Random(System.currentTimeMillis());
		r.nextBytes(encodedKey.getBytes());
		if (type.name().startsWith("BCPQC_MCELIECE_")) {
			try(ClientASymmetricEncryptionAlgorithm client = new ClientASymmetricEncryptionAlgorithm(SecureRandomType.DEFAULT.getInstance(null), publicKey)) {
				return client.encode(encodedKey.getBytes()).length;
			}
		}
		AsymmetricRSAPublicKey bcPK = (AsymmetricRSAPublicKey) publicKey.toBouncyCastleKey();



		OAEPParameters OAEPParams = type.getOAEPParams(PSource.PSpecified.DEFAULT.getValue());
		FipsRSA.KeyWrapOperatorFactory wrapFact = new FipsRSA.KeyWrapOperatorFactory();
		KeyWrapperUsingSecureRandom<FipsRSA.WrapParameters> wrapper =
				wrapFact.createKeyWrapper(bcPK, OAEPParams)
						.withSecureRandom(SecureRandomType.DEFAULT.getInstance(null));


		byte[] wrapedKey = wrapper.wrap(encodedKey.getBytes(), 0, encodedKey.getBytes().length);
		if (type.withParameters) {
			return wrapedKey.length+2+SymmetricSecretKey.ENCODED_TYPE_SIZE+OAEPParams.getEncodingParams().length+2;
		} else
			return wrapedKey.length+2+SymmetricSecretKey.ENCODED_TYPE_SIZE;
	}

	public ASymmetricKeyWrapperType getDerivedType() {
		return derivedType;
	}
	public AbstractKeyPairGenerator getKeyPairGenerator(AbstractSecureRandom random)
			throws NoSuchAlgorithmException, NoSuchProviderException, IOException {
		return getKeyPairGenerator(random, aSymmetricEncryptionType.getDefaultKeySizeBits(), System.currentTimeMillis(), System.currentTimeMillis() + aSymmetricEncryptionType.getDefaultExpirationTimeMilis());
	}

	public AbstractKeyPairGenerator getKeyPairGenerator(AbstractSecureRandom random, int keySizeBits)
			throws NoSuchAlgorithmException, NoSuchProviderException, IOException {
		return getKeyPairGenerator(random, keySizeBits, System.currentTimeMillis(), System.currentTimeMillis() + aSymmetricEncryptionType.getDefaultExpirationTimeMilis());
	}
	public AbstractKeyPairGenerator getKeyPairGenerator(AbstractSecureRandom random, int keySizeBits,
														long publicKeyValidityBeginDateUTC, long expirationTimeUTC) throws NoSuchAlgorithmException, NoSuchProviderException, IOException {
		return aSymmetricEncryptionType.getKeyPairGenerator(random, keySizeBits,publicKeyValidityBeginDateUTC, expirationTimeUTC);
	}

	public static final int MAX_SIZE_IN_BYTES_OF_WRAPPED_SYMMETRIC_SECRET_KEY_WITH_ASYMMETRIC_NON_PQC_ENCRYPTION =768;
	public static final int MAX_SIZE_IN_BYTES_OF_WRAPPED_SYMMETRIC_SECRET_KEY_WITH_ASYMMETRIC_PQC_ENCRYPTION =512;
	public static final int MAX_SIZE_IN_BYTES_OF_WRAPPED_SYMMETRIC_SECRET_KEY_WITH_ASYMMETRIC_HYBRID_ENCRYPTION =1024;

	public static final int MAX_SIZE_IN_BYTES_OF_WRAPPED_SYMMETRIC_SECRET_KEY_WITH_ASYMMETRIC_NON_PQC_ENCRYPTION_WITH_SYMMETRIC_SIGNATURE =768+SymmetricKeyWrapperType.MAX_SIZE_IN_BYTES_OF_SYMMETRIC_SIGNATURE_META_DATA;
	public static final int MAX_SIZE_IN_BYTES_OF_WRAPPED_SYMMETRIC_SECRET_KEY_WITH_ASYMMETRIC_PQC_ENCRYPTION_WITH_SYMMETRIC_SIGNATURE =512+SymmetricKeyWrapperType.MAX_SIZE_IN_BYTES_OF_SYMMETRIC_SIGNATURE_META_DATA;
	public static final int MAX_SIZE_IN_BYTES_OF_WRAPPED_SYMMETRIC_SECRET_KEY_WITH_ASYMMETRIC_HYBRID_ENCRYPTION_WITH_SYMMETRIC_SIGNATURE =1024+SymmetricKeyWrapperType.MAX_SIZE_IN_BYTES_OF_SYMMETRIC_SIGNATURE_META_DATA;


	public static final int MAX_SIZE_IN_BYTES_OF_WRAPPED_SYMMETRIC_SECRET_KEY_WITH_ASYMMETRIC_NON_PQC_ENCRYPTION_WITH_ASYMMETRIC_SIGNATURE =768+SymmetricKeyWrapperType.MAX_SIZE_IN_BYTES_OF_ASYMMETRIC_SIGNATURE_META_DATA;
	public static final int MAX_SIZE_IN_BYTES_OF_WRAPPED_SYMMETRIC_SECRET_KEY_WITH_ASYMMETRIC_PQC_ENCRYPTION_WITH_ASYMMETRIC_SIGNATURE =512+SymmetricKeyWrapperType.MAX_SIZE_IN_BYTES_OF_ASYMMETRIC_SIGNATURE_META_DATA;
	public static final int MAX_SIZE_IN_BYTES_OF_WRAPPED_SYMMETRIC_SECRET_KEY_WITH_ASYMMETRIC_HYBRID_ENCRYPTION_WITH_ASYMMETRIC_SIGNATURE =1024+SymmetricKeyWrapperType.MAX_SIZE_IN_BYTES_OF_ASYMMETRIC_SIGNATURE_META_DATA;

	public static final int MAX_SIZE_IN_BYTES_OF_WRAPPED_SYMMETRIC_SECRET_KEY_WITH_ASYMMETRIC_NON_PQC_ENCRYPTION_WITH_HYBRID_ASYMMETRIC_SIGNATURE =768+SymmetricKeyWrapperType.MAX_SIZE_IN_BYTES_OF_HYBRID_ASYMMETRIC_SIGNATURE_META_DATA;
	public static final int MAX_SIZE_IN_BYTES_OF_WRAPPED_SYMMETRIC_SECRET_KEY_WITH_ASYMMETRIC_PQC_ENCRYPTION_WITH_HYBRID_ASYMMETRIC_SIGNATURE =512+SymmetricKeyWrapperType.MAX_SIZE_IN_BYTES_OF_HYBRID_ASYMMETRIC_SIGNATURE_META_DATA;
	public static final int MAX_SIZE_IN_BYTES_OF_WRAPPED_SYMMETRIC_SECRET_KEY_WITH_ASYMMETRIC_HYBRID_ENCRYPTION_WITH_HYBRID_ASYMMETRIC_SIGNATURE =1024+SymmetricKeyWrapperType.MAX_SIZE_IN_BYTES_OF_HYBRID_ASYMMETRIC_SIGNATURE_META_DATA;

	public static final int MAX_SIZE_IN_BYTES_OF_WRAPPED_SYMMETRIC_SECRET_KEY_WITH_ASYMMETRIC_NON_PQC_ENCRYPTION_WITH_SYMMETRIC_AND_HYBRID_ASYMMETRIC_SIGNATURE =768+SymmetricKeyWrapperType.MAX_SIZE_IN_BYTES_OF_HYBRID_SIGNATURE_META_DATA;
	public static final int MAX_SIZE_IN_BYTES_OF_WRAPPED_SYMMETRIC_SECRET_KEY_WITH_ASYMMETRIC_PQC_ENCRYPTION_WITH_SYMMETRIC_AND_HYBRID_ASYMMETRIC_SIGNATURE =512+SymmetricKeyWrapperType.MAX_SIZE_IN_BYTES_OF_HYBRID_SIGNATURE_META_DATA;
	public static final int MAX_SIZE_IN_BYTES_OF_WRAPPED_SYMMETRIC_SECRET_KEY_WITH_ASYMMETRIC_HYBRID_ENCRYPTION_WITH_SYMMETRIC_AND_HYBRID_ASYMMETRIC_SIGNATURE =1024+SymmetricKeyWrapperType.MAX_SIZE_IN_BYTES_OF_HYBRID_SIGNATURE_META_DATA;

	public static final int MAX_SIZE_IN_BYTES_OF_WRAPPED_ASYMMETRIC_PRIVATE_KEY_WITHOUT_RSA_FOR_SIGNATURE_WITH_ASYMMETRIC_NON_PQC_ENCRYPTION =1024;
	public static final int MAX_SIZE_IN_BYTES_OF_WRAPPED_ASYMMETRIC_PRIVATE_KEY_WITHOUT_RSA_FOR_SIGNATURE_WITH_ASYMMETRIC_PQC_ENCRYPTION =512;
	public static final int MAX_SIZE_IN_BYTES_OF_WRAPPED_ASYMMETRIC_PRIVATE_KEY_WITHOUT_RSA_FOR_SIGNATURE_WITH_ASYMMETRIC_HYBRID_ENCRYPTION =1024;

	public static final int MAX_SIZE_IN_BYTES_OF_WRAPPED_ASYMMETRIC_PRIVATE_KEY_WITHOUT_RSA_FOR_SIGNATURE_WITH_ASYMMETRIC_NON_PQC_ENCRYPTION_WITH_SYMMETRIC_SIGNATURE =1024+SymmetricKeyWrapperType.MAX_SIZE_IN_BYTES_OF_SYMMETRIC_SIGNATURE_META_DATA;
	public static final int MAX_SIZE_IN_BYTES_OF_WRAPPED_ASYMMETRIC_PRIVATE_KEY_WITHOUT_RSA_FOR_SIGNATURE_WITH_ASYMMETRIC_PQC_ENCRYPTION_WITH_SYMMETRIC_SIGNATURE =512+SymmetricKeyWrapperType.MAX_SIZE_IN_BYTES_OF_SYMMETRIC_SIGNATURE_META_DATA;
	public static final int MAX_SIZE_IN_BYTES_OF_WRAPPED_ASYMMETRIC_PRIVATE_KEY_WITHOUT_RSA_FOR_SIGNATURE_WITH_ASYMMETRIC_HYBRID_ENCRYPTION_WITH_SYMMETRIC_SIGNATURE =1024+SymmetricKeyWrapperType.MAX_SIZE_IN_BYTES_OF_SYMMETRIC_SIGNATURE_META_DATA;

	public static final int MAX_SIZE_IN_BYTES_OF_WRAPPED_ASYMMETRIC_PRIVATE_KEY_WITHOUT_RSA_FOR_SIGNATURE_WITH_ASYMMETRIC_NON_PQC_ENCRYPTION_WITH_ASYMMETRIC_SIGNATURE =1024+SymmetricKeyWrapperType.MAX_SIZE_IN_BYTES_OF_ASYMMETRIC_SIGNATURE_META_DATA;
	public static final int MAX_SIZE_IN_BYTES_OF_WRAPPED_ASYMMETRIC_PRIVATE_KEY_WITHOUT_RSA_FOR_SIGNATURE_WITH_ASYMMETRIC_PQC_ENCRYPTION_WITH_ASYMMETRIC_SIGNATURE =512+SymmetricKeyWrapperType.MAX_SIZE_IN_BYTES_OF_ASYMMETRIC_SIGNATURE_META_DATA;
	public static final int MAX_SIZE_IN_BYTES_OF_WRAPPED_ASYMMETRIC_PRIVATE_KEY_WITHOUT_RSA_FOR_SIGNATURE_WITH_ASYMMETRIC_HYBRID_ENCRYPTION_WITH_ASYMMETRIC_SIGNATURE =1024+SymmetricKeyWrapperType.MAX_SIZE_IN_BYTES_OF_ASYMMETRIC_SIGNATURE_META_DATA;

	public static final int MAX_SIZE_IN_BYTES_OF_WRAPPED_ASYMMETRIC_PRIVATE_KEY_WITHOUT_RSA_FOR_SIGNATURE_WITH_ASYMMETRIC_NON_PQC_ENCRYPTION_WITH_HYBRID_ASYMMETRIC_SIGNATURE =1024+SymmetricKeyWrapperType.MAX_SIZE_IN_BYTES_OF_HYBRID_ASYMMETRIC_SIGNATURE_META_DATA;
	public static final int MAX_SIZE_IN_BYTES_OF_WRAPPED_ASYMMETRIC_PRIVATE_KEY_WITHOUT_RSA_FOR_SIGNATURE_WITH_ASYMMETRIC_PQC_ENCRYPTION_WITH_HYBRID_ASYMMETRIC_SIGNATURE =512+SymmetricKeyWrapperType.MAX_SIZE_IN_BYTES_OF_HYBRID_ASYMMETRIC_SIGNATURE_META_DATA;
	public static final int MAX_SIZE_IN_BYTES_OF_WRAPPED_ASYMMETRIC_PRIVATE_KEY_WITHOUT_RSA_FOR_SIGNATURE_WITH_ASYMMETRIC_HYBRID_ENCRYPTION_WITH_HYBRID_ASYMMETRIC_SIGNATURE =1024+SymmetricKeyWrapperType.MAX_SIZE_IN_BYTES_OF_HYBRID_ASYMMETRIC_SIGNATURE_META_DATA;

	public static final int MAX_SIZE_IN_BYTES_OF_WRAPPED_ASYMMETRIC_PRIVATE_KEY_WITHOUT_RSA_FOR_SIGNATURE_WITH_ASYMMETRIC_NON_PQC_ENCRYPTION_WITH_SYMMETRIC_AND_HYBRID_ASYMMETRIC_SIGNATURE =1024+SymmetricKeyWrapperType.MAX_SIZE_IN_BYTES_OF_HYBRID_SIGNATURE_META_DATA;
	public static final int MAX_SIZE_IN_BYTES_OF_WRAPPED_ASYMMETRIC_PRIVATE_KEY_WITHOUT_RSA_FOR_SIGNATURE_WITH_ASYMMETRIC_PQC_ENCRYPTION_WITH_SYMMETRIC_AND_HYBRID_ASYMMETRIC_SIGNATURE =512+SymmetricKeyWrapperType.MAX_SIZE_IN_BYTES_OF_HYBRID_SIGNATURE_META_DATA;
	public static final int MAX_SIZE_IN_BYTES_OF_WRAPPED_ASYMMETRIC_PRIVATE_KEY_WITHOUT_RSA_FOR_SIGNATURE_WITH_ASYMMETRIC_HYBRID_ENCRYPTION_WITH_SYMMETRIC_AND_HYBRID_ASYMMETRIC_SIGNATURE =1024+SymmetricKeyWrapperType.MAX_SIZE_IN_BYTES_OF_HYBRID_SIGNATURE_META_DATA;

	public static final int MAX_SIZE_IN_BYTES_OF_WRAPPED_ASYMMETRIC_NON_PQC_NON_RSA_NON_HYBRID_PRIVATE_KEY_FOR_SIGNATURE_WITH_ASYMMETRIC_NON_PQC_ENCRYPTION =1024;
	public static final int MAX_SIZE_IN_BYTES_OF_WRAPPED_ASYMMETRIC_NON_PQC_NON_RSA_NON_HYBRID_PRIVATE_KEY_FOR_SIGNATURE_WITH_ASYMMETRIC_PQC_ENCRYPTION =512;
	public static final int MAX_SIZE_IN_BYTES_OF_WRAPPED_ASYMMETRIC_NON_PQC_NON_RSA_NON_HYBRID_PRIVATE_KEY_FOR_SIGNATURE_WITH_ASYMMETRIC_HYBRID_ENCRYPTION =1024;

	public static final int MAX_SIZE_IN_BYTES_OF_WRAPPED_ASYMMETRIC_NON_PQC_NON_RSA_NON_HYBRID_PRIVATE_KEY_FOR_SIGNATURE_WITH_ASYMMETRIC_NON_PQC_ENCRYPTION_WITH_SYMMETRIC_SIGNATURE =1024+SymmetricKeyWrapperType.MAX_SIZE_IN_BYTES_OF_SYMMETRIC_SIGNATURE_META_DATA;
	public static final int MAX_SIZE_IN_BYTES_OF_WRAPPED_ASYMMETRIC_NON_PQC_NON_RSA_NON_HYBRID_PRIVATE_KEY_FOR_SIGNATURE_WITH_ASYMMETRIC_PQC_ENCRYPTION_WITH_SYMMETRIC_SIGNATURE =512+SymmetricKeyWrapperType.MAX_SIZE_IN_BYTES_OF_SYMMETRIC_SIGNATURE_META_DATA;
	public static final int MAX_SIZE_IN_BYTES_OF_WRAPPED_ASYMMETRIC_NON_PQC_NON_RSA_NON_HYBRID_PRIVATE_KEY_FOR_SIGNATURE_WITH_ASYMMETRIC_HYBRID_ENCRYPTION_WITH_SYMMETRIC_SIGNATURE =1024+SymmetricKeyWrapperType.MAX_SIZE_IN_BYTES_OF_SYMMETRIC_SIGNATURE_META_DATA;

	public static final int MAX_SIZE_IN_BYTES_OF_WRAPPED_ASYMMETRIC_NON_PQC_NON_RSA_NON_HYBRID_PRIVATE_KEY_FOR_SIGNATURE_WITH_ASYMMETRIC_NON_PQC_ENCRYPTION_WITH_ASYMMETRIC_SIGNATURE =1024+SymmetricKeyWrapperType.MAX_SIZE_IN_BYTES_OF_ASYMMETRIC_SIGNATURE_META_DATA;
	public static final int MAX_SIZE_IN_BYTES_OF_WRAPPED_ASYMMETRIC_NON_PQC_NON_RSA_NON_HYBRID_PRIVATE_KEY_FOR_SIGNATURE_WITH_ASYMMETRIC_PQC_ENCRYPTION_WITH_ASYMMETRIC_SIGNATURE =512+SymmetricKeyWrapperType.MAX_SIZE_IN_BYTES_OF_ASYMMETRIC_SIGNATURE_META_DATA;
	public static final int MAX_SIZE_IN_BYTES_OF_WRAPPED_ASYMMETRIC_NON_PQC_NON_RSA_NON_HYBRID_PRIVATE_KEY_FOR_SIGNATURE_WITH_ASYMMETRIC_HYBRID_ENCRYPTION_WITH_ASYMMETRIC_SIGNATURE =1024+SymmetricKeyWrapperType.MAX_SIZE_IN_BYTES_OF_ASYMMETRIC_SIGNATURE_META_DATA;

	public static final int MAX_SIZE_IN_BYTES_OF_WRAPPED_ASYMMETRIC_NON_PQC_NON_RSA_NON_HYBRID_PRIVATE_KEY_FOR_SIGNATURE_WITH_ASYMMETRIC_NON_PQC_ENCRYPTION_WITH_HYBRID_ASYMMETRIC_SIGNATURE =1024+SymmetricKeyWrapperType.MAX_SIZE_IN_BYTES_OF_HYBRID_ASYMMETRIC_SIGNATURE_META_DATA;
	public static final int MAX_SIZE_IN_BYTES_OF_WRAPPED_ASYMMETRIC_NON_PQC_NON_RSA_NON_HYBRID_PRIVATE_KEY_FOR_SIGNATURE_WITH_ASYMMETRIC_PQC_ENCRYPTION_WITH_HYBRID_ASYMMETRIC_SIGNATURE =512+SymmetricKeyWrapperType.MAX_SIZE_IN_BYTES_OF_HYBRID_ASYMMETRIC_SIGNATURE_META_DATA;
	public static final int MAX_SIZE_IN_BYTES_OF_WRAPPED_ASYMMETRIC_NON_PQC_NON_RSA_NON_HYBRID_PRIVATE_KEY_FOR_SIGNATURE_WITH_ASYMMETRIC_HYBRID_ENCRYPTION_WITH_HYBRID_ASYMMETRIC_SIGNATURE =1024+SymmetricKeyWrapperType.MAX_SIZE_IN_BYTES_OF_HYBRID_ASYMMETRIC_SIGNATURE_META_DATA;

	public static final int MAX_SIZE_IN_BYTES_OF_WRAPPED_ASYMMETRIC_NON_PQC_NON_RSA_NON_HYBRID_PRIVATE_KEY_FOR_SIGNATURE_WITH_ASYMMETRIC_NON_PQC_ENCRYPTION_WITH_SYMMETRIC_AND_HYBRID_ASYMMETRIC_SIGNATURE =1024+SymmetricKeyWrapperType.MAX_SIZE_IN_BYTES_OF_HYBRID_SIGNATURE_META_DATA;
	public static final int MAX_SIZE_IN_BYTES_OF_WRAPPED_ASYMMETRIC_NON_PQC_NON_RSA_NON_HYBRID_PRIVATE_KEY_FOR_SIGNATURE_WITH_ASYMMETRIC_PQC_ENCRYPTION_WITH_SYMMETRIC_AND_HYBRID_ASYMMETRIC_SIGNATURE =512+SymmetricKeyWrapperType.MAX_SIZE_IN_BYTES_OF_HYBRID_SIGNATURE_META_DATA;
	public static final int MAX_SIZE_IN_BYTES_OF_WRAPPED_ASYMMETRIC_NON_PQC_NON_RSA_NON_HYBRID_PRIVATE_KEY_FOR_SIGNATURE_WITH_ASYMMETRIC_HYBRID_ENCRYPTION_WITH_SYMMETRIC_AND_HYBRID_ASYMMETRIC_SIGNATURE =1024+SymmetricKeyWrapperType.MAX_SIZE_IN_BYTES_OF_HYBRID_SIGNATURE_META_DATA;

}

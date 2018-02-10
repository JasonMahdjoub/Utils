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
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchProviderException;
import java.security.spec.MGF1ParameterSpec;

import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

import org.bouncycastle.crypto.InvalidWrappingException;
import org.bouncycastle.crypto.KeyUnwrapperUsingSecureRandom;
import org.bouncycastle.crypto.KeyWrapperUsingSecureRandom;
import org.bouncycastle.crypto.asymmetric.AsymmetricRSAPrivateKey;
import org.bouncycastle.crypto.asymmetric.AsymmetricRSAPublicKey;
import org.bouncycastle.crypto.fips.FipsDigestAlgorithm;
import org.bouncycastle.crypto.fips.FipsRSA;
import org.bouncycastle.crypto.fips.FipsSHS;
import org.bouncycastle.crypto.fips.FipsRSA.OAEPParameters;
import org.bouncycastle.crypto.fips.FipsRSA.WrapParameters;

import com.distrimind.util.Bits;
import com.distrimind.util.OSValidator;

import gnu.vm.jgnu.security.InvalidKeyException;
import gnu.vm.jgnu.security.NoSuchAlgorithmException;
import gnu.vm.jgnu.security.spec.InvalidKeySpecException;
import gnu.vm.jgnux.crypto.Cipher;
import gnu.vm.jgnux.crypto.IllegalBlockSizeException;
import gnu.vm.jgnux.crypto.NoSuchPaddingException;
import gnu.vm.jgnux.crypto.SecretKey;

/**
 * 
 * @author Jason Mahdjoub
 * @version 1.1
 * @since Utils 1.17.0
 */
public enum ASymmetricKeyWrapperType {

	RSA_OAEP_WITH_SHA2_384("RSA/ECB/OAEPPadding",CodeProvider.SunJCE, false, "SHA-384", FipsSHS.Algorithm.SHA384),
	RSA_OAEP_WITH_PARAMETERS_SHA2_384("RSA/ECB/OAEPPadding",CodeProvider.SunJCE, true, "SHA-384", FipsSHS.Algorithm.SHA384),
	GNU_RSA_OAEP_SHA2_384("RSA/NONE/OAEPPadding",CodeProvider.GNU_CRYPTO, false, "SHA-384", FipsSHS.Algorithm.SHA384),
	RSA_OAEP_SHA2_512("RSA/ECB/OAEPPadding",CodeProvider.SunJCE, false, "SHA-512", FipsSHS.Algorithm.SHA512),
	RSA_OAEP_WITH_PARAMETERS_SHA2_512("RSA/ECB/OAEPPadding",CodeProvider.SunJCE, true, "SHA-512", FipsSHS.Algorithm.SHA512),
	GNU_RSA_OAEP_SHA2_512("RSA/NONE/OAEPPadding",CodeProvider.GNU_CRYPTO, false, "SHA-512", FipsSHS.Algorithm.SHA512),
	BC_FIPS_RSA_OAEP_WITH_SHA2_384("RSA/NONE/OAEPPadding",CodeProvider.BCFIPS, false, "SHA-384", FipsSHS.Algorithm.SHA384),
	BC_FIPS_RSA_OAEP_WITH_PARAMETERS_SHA2_384("RSA/NONE/OAEPPadding",CodeProvider.BCFIPS, true, "SHA-384", FipsSHS.Algorithm.SHA384),
	BC_FIPS_RSA_OAEP_SHA2_512("RSA/NONE/OAEPPadding",CodeProvider.BCFIPS, false, "SHA-384", FipsSHS.Algorithm.SHA512),
	BC_FIPS_RSA_OAEP_WITH_PARAMETERS_SHA2_512("RSA/NONE/OAEPPadding",CodeProvider.BCFIPS, true, "SHA-384", FipsSHS.Algorithm.SHA512),
	BC_FIPS_RSA_OAEP_WITH_SHA3_384("RSA/NONE/OAEPPadding",CodeProvider.BCFIPS, false, "SHA-384", FipsSHS.Algorithm.SHA3_384),
	BC_FIPS_RSA_OAEP_WITH_PARAMETERS_SHA3_384("RSA/NONE/OAEPPadding",CodeProvider.BCFIPS, true, "SHA-384", FipsSHS.Algorithm.SHA3_384),
	BC_FIPS_RSA_OAEP_SHA3_512("RSA/NONE/OAEPPadding",CodeProvider.BCFIPS, false, "SHA-384", FipsSHS.Algorithm.SHA3_512),
	BC_FIPS_RSA_OAEP_WITH_PARAMETERS_SHA3_512("RSA/NONE/OAEPPadding",CodeProvider.BCFIPS, true, "SHA-384", FipsSHS.Algorithm.SHA3_512),
	//BC_FIPS_RSA_KTS_KTM("RSA-KTS-KEM-KWS",CodeProvider.BCFIPS, false),
	DEFAULT(BC_FIPS_RSA_OAEP_WITH_PARAMETERS_SHA3_384);
	
	
	
	private final String algorithmName;
	private final CodeProvider provider;
	private final boolean withParameters;
	private final String shaAlgorithm;
	private final FipsDigestAlgorithm bcShaDigestAlgorithm;
	
	
	private ASymmetricKeyWrapperType(String algorithmName, CodeProvider provider, boolean withParameters, String shaAlgorithm, FipsDigestAlgorithm bcShaDigestAlgorithm) {
		this.algorithmName = algorithmName;
		this.provider = provider;
		this.withParameters=withParameters;
		this.shaAlgorithm=shaAlgorithm;
		this.bcShaDigestAlgorithm=bcShaDigestAlgorithm;
	}
	
	private ASymmetricKeyWrapperType(ASymmetricKeyWrapperType other)
	{
		this(other.algorithmName, other.provider, other.withParameters, other.shaAlgorithm, other.bcShaDigestAlgorithm);
	}
	
	public CodeProvider getCodeProvider()
	{
		return provider;
	}
	public String getAlgorithmName()
	{
		return algorithmName;
	}	
	
	static byte[] wrapKeyWithMetaData(byte[] wrappedKey, SymmetricSecretKey keyToWrap)
	{
		byte[] res=new byte[wrappedKey.length+7];
		res[0]=keyToWrap.getAuthentifiedSignatureAlgorithmType()!=null?(byte)1:(byte)0;
		Bits.putInt(res, 1, keyToWrap.getAuthentifiedSignatureAlgorithmType()!=null?keyToWrap.getAuthentifiedSignatureAlgorithmType().ordinal():keyToWrap.getEncryptionAlgorithmType().ordinal());
		Bits.putShort(res, 5, keyToWrap.getKeySizeBits());
		System.arraycopy(wrappedKey, 0, res, 7, wrappedKey.length);
		return res;
	}
	static byte[] getWrappedKeyFromMetaData(byte[] wk) throws InvalidKeyException
	{
		if (wk.length<9)
			throw new InvalidKeyException();
		byte[] res=new byte[wk.length-7];
		System.arraycopy(wk, 7, res, 0, res.length);
		return res;
	}
	static boolean isSignatureFromMetaData(byte[] wk) throws InvalidKeyException
	{
		if (wk.length<9)
			throw new InvalidKeyException();
		return wk[0]==1;
	}
	static short getKeySizeFromMetaData(byte[] wk) throws InvalidKeyException
	{
		if (wk.length<9)
			throw new InvalidKeyException();
		return Bits.getShort(wk, 5);
	}
	
	static SymmetricAuthentifiedSignatureType getSignatureTypeFromMetaData(byte[] wk) throws InvalidKeyException
	{
		if (wk.length<9)
			throw new InvalidKeyException();
		int ordinal=Bits.getInt(wk, 1);
		for (SymmetricAuthentifiedSignatureType t : SymmetricAuthentifiedSignatureType.values())
		{
			if (t.ordinal()==ordinal)
				return t;
		}
		throw new InvalidKeyException();
	}
	static SymmetricEncryptionType getEncryptionTypeFromMetaData(byte[] wk) throws InvalidKeyException
	{
		if (wk.length<9)
			throw new InvalidKeyException();
		int ordinal=Bits.getInt(wk, 1);
		for (SymmetricEncryptionType t : SymmetricEncryptionType.values())
		{
			if (t.ordinal()==ordinal)
				return t;
		}
		throw new InvalidKeyException();
	}
	
	private OAEPParameters getOAEPParams(byte params[])
	{
		OAEPParameters OAEPParams=FipsRSA.WRAP_OAEP;
		if (withParameters)
			OAEPParams=OAEPParams.withMGFDigest(bcShaDigestAlgorithm)
						.withEncodingParams(params);
		return OAEPParams;
	}
	
	public byte[] wrapKey(AbstractSecureRandom random, ASymmetricPublicKey publicKey, SymmetricSecretKey keyToWrap) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IllegalStateException, IllegalBlockSizeException, gnu.vm.jgnu.security.NoSuchProviderException, gnu.vm.jgnu.security.InvalidAlgorithmParameterException, IOException
	{
		if ((publicKey.getAuthentifiedSignatureAlgorithmType()!=null && ((provider==CodeProvider.GNU_CRYPTO)!=(publicKey.getAuthentifiedSignatureAlgorithmType().getCodeProviderForSignature()==CodeProvider.GNU_CRYPTO))) 
				|| (publicKey.getEncryptionAlgorithmType()!=null  && ((provider==CodeProvider.GNU_CRYPTO)!=(publicKey.getEncryptionAlgorithmType().getCodeProviderForEncryption()==CodeProvider.GNU_CRYPTO)))
				|| (keyToWrap.getAuthentifiedSignatureAlgorithmType()!=null && (provider==CodeProvider.GNU_CRYPTO)!=(keyToWrap.getAuthentifiedSignatureAlgorithmType().getCodeProviderForSignature()==CodeProvider.GNU_CRYPTO))
				|| (keyToWrap.getEncryptionAlgorithmType()!=null && (provider==CodeProvider.GNU_CRYPTO)!=(keyToWrap.getEncryptionAlgorithmType().getCodeProviderForEncryption()==CodeProvider.GNU_CRYPTO)))
				throw new IllegalArgumentException("The keys must come from the same providers");
		
		if (provider.equals(CodeProvider.GNU_CRYPTO))
		{
			Cipher c = Cipher.getInstance(algorithmName);
			c.init(Cipher.WRAP_MODE, publicKey.toGnuKey(), random.getGnuSecureRandom());
			return wrapKeyWithMetaData(c.wrap(keyToWrap.toGnuKey()), keyToWrap);
		}
		else
		{
			try
			{
				javax.crypto.Cipher c=null;
				if (provider.equals(CodeProvider.BCFIPS) || (OSValidator.getCurrentOS()==OSValidator.MACOS && (this.getCodeProvider()==CodeProvider.SunJCE)))
				{
					CodeProvider.ensureBouncyCastleProviderLoaded();
					
					
					
					
					AsymmetricRSAPublicKey bcPK=(AsymmetricRSAPublicKey)publicKey.toBouncyCastleKey();
					
					byte encodedKey []=keyToWrap.encode();
					
					OAEPParameters OAEPParams=getOAEPParams(PSource.PSpecified.DEFAULT.getValue());
					
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
						
						
						
					byte[] wrapedKey=wrapper.wrap(encodedKey, 0, encodedKey.length);
					
					if (withParameters)
					{
						byte[] encodedParameters=OAEPParams.getEncodingParams();
						return wrapKeyWithMetaData(Bits.concateEncodingWithShortSizedTabs(wrapedKey, encodedParameters), keyToWrap);
					}
					else
						return wrapKeyWithMetaData(wrapedKey, keyToWrap);
					
				}
				/*if (OSValidator.getCurrentOS()==OSValidator.MACOS && (this==RSA_OAEP || this==ASymmetricKeyWrapperType.RSA_OAEP_WITH_PARAMETERS))
				{
					CodeProvider.ensureBouncyCastleProviderLoaded();
				
					c=javax.crypto.Cipher.getInstance(algorithmName, CodeProvider.BCFIPS.name());
				}*/
				else
					c=javax.crypto.Cipher.getInstance(algorithmName, provider.checkProviderWithCurrentOS().name());

				if (withParameters)
				{
					c.init(javax.crypto.Cipher.WRAP_MODE, publicKey.toJavaNativeKey(),
							new OAEPParameterSpec(shaAlgorithm,"MGF1",new MGF1ParameterSpec(shaAlgorithm),PSource.PSpecified.DEFAULT), random);
					byte[] wrapedKey=c.wrap(keyToWrap.toJavaNativeKey());
					byte[] encodedParameters=c.getParameters().getEncoded();
					return wrapKeyWithMetaData(Bits.concateEncodingWithShortSizedTabs(wrapedKey, encodedParameters), keyToWrap);
				}
				/*else if (this.algorithmName.equals(BC_FIPS_RSA_KTS_KTM.algorithmName))
				{
					c.init(javax.crypto.Cipher.WRAP_MODE, publicKey.toJavaNativeKey(), new KTSParameterSpec.Builder(NISTObjectIdentifiers.id_aes256_wrap.getId(),256).build(), random);
					return wrapKeyWithMetaData(c.wrap(keyToWrap.toJavaNativeKey()), keyToWrap);
				}*/
				else
				{
					c.init(javax.crypto.Cipher.WRAP_MODE, publicKey.toJavaNativeKey(), random);

					return wrapKeyWithMetaData(c.wrap(keyToWrap.toJavaNativeKey()), keyToWrap);
				}
				
			}
			catch(java.security.NoSuchAlgorithmException e)
			{
				throw new NoSuchAlgorithmException(e);
			}
			catch(javax.crypto.NoSuchPaddingException e)
			{
				throw new NoSuchPaddingException(e.getMessage()+" "+ this);
			}
			catch(java.security.InvalidKeyException e)
			{
				throw new InvalidKeyException(e);
			}
			catch(javax.crypto.IllegalBlockSizeException e)
			{
				throw new IllegalBlockSizeException(e.getMessage());
			}
			catch(NoSuchProviderException e)
			{
				throw new gnu.vm.jgnu.security.NoSuchProviderException(e.getMessage());
			} catch (InvalidAlgorithmParameterException e) {
				throw new gnu.vm.jgnu.security.InvalidAlgorithmParameterException(e);
			}
			
		}
	}
	
	public SymmetricSecretKey unwrapKey(ASymmetricPrivateKey privateKey, byte[] keyToUnwrap) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalStateException, gnu.vm.jgnu.security.NoSuchProviderException, InvalidKeySpecException, gnu.vm.jgnu.security.InvalidAlgorithmParameterException, IOException, IllegalArgumentException, InvalidWrappingException
	{
		if (isSignatureFromMetaData(keyToUnwrap))
			return unwrapKey(privateKey, getWrappedKeyFromMetaData(keyToUnwrap), null, getSignatureTypeFromMetaData(keyToUnwrap), getKeySizeFromMetaData(keyToUnwrap));
		else
			return unwrapKey(privateKey, getWrappedKeyFromMetaData(keyToUnwrap), getEncryptionTypeFromMetaData(keyToUnwrap), null, getKeySizeFromMetaData(keyToUnwrap));
		
	}
	private SymmetricSecretKey unwrapKey(ASymmetricPrivateKey privateKey, byte[] keyToUnwrap, SymmetricEncryptionType encryptionType, SymmetricAuthentifiedSignatureType signatureType, short keySize) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalStateException, gnu.vm.jgnu.security.NoSuchProviderException, InvalidKeySpecException, IOException, gnu.vm.jgnu.security.InvalidAlgorithmParameterException, IllegalArgumentException, InvalidWrappingException
	{
		if ((privateKey.getAuthentifiedSignatureAlgorithmType()!=null && ((provider==CodeProvider.GNU_CRYPTO)!=(privateKey.getAuthentifiedSignatureAlgorithmType().getCodeProviderForSignature()==CodeProvider.GNU_CRYPTO))) 
				|| (privateKey.getEncryptionAlgorithmType()!=null  && ((provider==CodeProvider.GNU_CRYPTO)!=(privateKey.getEncryptionAlgorithmType().getCodeProviderForEncryption()==CodeProvider.GNU_CRYPTO)))
				|| (encryptionType!=null && (provider==CodeProvider.GNU_CRYPTO)!=(encryptionType.getCodeProviderForEncryption()==CodeProvider.GNU_CRYPTO))
				|| (signatureType!=null && (provider==CodeProvider.GNU_CRYPTO)!=(signatureType.getCodeProviderForSignature()==CodeProvider.GNU_CRYPTO)))
				throw new IllegalArgumentException("The keys must come from the same providers");
		if (provider.equals(CodeProvider.GNU_CRYPTO))
		{
			Cipher c = Cipher.getInstance(algorithmName);
			c.init(Cipher.UNWRAP_MODE, privateKey.toGnuKey());
			if (encryptionType==null)
			{
				return new SymmetricSecretKey(signatureType, (SecretKey)c.unwrap(keyToUnwrap, signatureType.getAlgorithmName(), Cipher.SECRET_KEY), keySize);
			}
			else
				return new SymmetricSecretKey(encryptionType, (SecretKey)c.unwrap(keyToUnwrap, encryptionType.getAlgorithmName(), Cipher.SECRET_KEY), keySize);
			
		}
		else
		{
			try
			{
				
				
				javax.crypto.Cipher c=null;
				if (provider.equals(CodeProvider.BCFIPS) || (OSValidator.getCurrentOS()==OSValidator.MACOS && (this.getCodeProvider()==CodeProvider.SunJCE)))
				{
					CodeProvider.ensureBouncyCastleProviderLoaded();
					
					AsymmetricRSAPrivateKey bcPK=(AsymmetricRSAPrivateKey)privateKey.toBouncyCastleKey();
					
					OAEPParameters OAEPParams=null;
					
					byte[] wrapedKey=null;
					if (withParameters)
					{
						byte[][] tmp=Bits.separateEncodingsWithShortSizedTabs(keyToUnwrap);
						wrapedKey=tmp[0];
						OAEPParams=getOAEPParams(tmp[1]);
					}
					else
					{
						wrapedKey=keyToUnwrap;
						OAEPParams=getOAEPParams(null);
					}
					
					
					FipsRSA.KeyWrapOperatorFactory wrapFact = new FipsRSA.KeyWrapOperatorFactory();
					KeyUnwrapperUsingSecureRandom<WrapParameters> unwrapper = 
							wrapFact.createKeyUnwrapper(bcPK,OAEPParams)
							.withSecureRandom(SecureRandomType.DEFAULT.getSingleton(null));
					return (SymmetricSecretKey)Key.decode(unwrapper.unwrap(wrapedKey, 0, wrapedKey.length));
					
				}
				/*if (OSValidator.getCurrentOS()==OSValidator.MACOS && (this==RSA_OAEP || this==ASymmetricKeyWrapperType.RSA_OAEP_WITH_PARAMETERS))
				{
					CodeProvider.ensureBouncyCastleProviderLoaded();
				
					c=javax.crypto.Cipher.getInstance(algorithmName, CodeProvider.BCFIPS.name());
				}*/
				else
					c=javax.crypto.Cipher.getInstance(algorithmName, provider.checkProviderWithCurrentOS().name());

				byte[] wrapedKey=null;
				if (withParameters)
				{
					byte[][] tmp=Bits.separateEncodingsWithShortSizedTabs(keyToUnwrap);
					wrapedKey=tmp[0];
					AlgorithmParameters algorithmParameters = AlgorithmParameters.getInstance("OAEP");
					algorithmParameters.init(tmp[1]);
					c.init(Cipher.UNWRAP_MODE, privateKey.toJavaNativeKey(), algorithmParameters);
				}
				/*else if (this.algorithmName.equals(BC_FIPS_RSA_KTS_KTM.algorithmName))
				{
					wrapedKey=keyToUnwrap;
					c.init(Cipher.UNWRAP_MODE, privateKey.toJavaNativeKey(), new KTSParameterSpec.Builder(NISTObjectIdentifiers.id_aes256_wrap.getId(),256).build());
				}*/
				else
				{
					wrapedKey=keyToUnwrap;
					c.init(Cipher.UNWRAP_MODE, privateKey.toJavaNativeKey());
				}
				if (encryptionType==null)
				{
					return new SymmetricSecretKey(signatureType, (javax.crypto.SecretKey)c.unwrap(wrapedKey, signatureType.getAlgorithmName(), javax.crypto.Cipher.SECRET_KEY), keySize);
				}
				else
					return new SymmetricSecretKey(encryptionType, (javax.crypto.SecretKey)c.unwrap(wrapedKey, encryptionType.getAlgorithmName(), javax.crypto.Cipher.SECRET_KEY), keySize);
				
			}
			catch(java.security.NoSuchAlgorithmException e)
			{
				throw new NoSuchAlgorithmException(e);
			}
			catch(javax.crypto.NoSuchPaddingException e)
			{
				throw new NoSuchPaddingException(e.getMessage());
			}
			catch(java.security.InvalidKeyException e)
			{
				throw new InvalidKeyException(e);
			}
			catch(NoSuchProviderException e)
			{
				throw new gnu.vm.jgnu.security.NoSuchProviderException(e.getMessage());
			} catch (InvalidAlgorithmParameterException e) {
				throw new gnu.vm.jgnu.security.InvalidAlgorithmParameterException(e);
			}
			
		}
		
	}
	
}

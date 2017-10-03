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

import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.jcajce.spec.KTSParameterSpec;

import com.distrimind.util.Bits;

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
 * @version 1.0
 * @since Utils 1.17.0
 */
public enum ASymmetricKeyWrapper {

	RSA_OAEP("RSA/NONE/OAEPPadding",CodeProvider.SUN, false),
	RSA_OAEP_WITH_PARAMETERS("RSA/NONE/OAEPPadding",CodeProvider.SUN, true),
	GNU_RSA_OAEP("RSA/NONE/OAEPPadding",CodeProvider.GNU_CRYPTO, false),
	BC_FIPS_RSA_OAEP("RSA/NONE/OAEPPadding",CodeProvider.BCFIPS, false),
	BC_FIPS_RSA_OAEP_WITH_PARAMETERS("RSA/NONE/OAEPPadding",CodeProvider.BCFIPS, true),
	BC_FIPS_RSA_KTS_KTM("RSA-KTS-KEM-KWS",CodeProvider.BCFIPS, false),
	DEFAULT(BC_FIPS_RSA_KTS_KTM);
	
	private final String algorithmName;
	private final CodeProvider provider;
	private final boolean withParameters;
	
	private ASymmetricKeyWrapper(String algorithmName, CodeProvider provider, boolean withParameters) {
		this.algorithmName = algorithmName;
		this.provider = provider;
		this.withParameters=withParameters;
	}
	
	private ASymmetricKeyWrapper(ASymmetricKeyWrapper other)
	{
		this(other.algorithmName, other.provider, other.withParameters);
	}
	
	public CodeProvider getCodeProvider()
	{
		return provider;
	}
	public String getAlgorithmName()
	{
		return algorithmName;
	}	
	
	public byte[] wrapKey(ASymmetricPublicKey publicKey, SymmetricSecretKey keyToWrap) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IllegalStateException, IllegalBlockSizeException, gnu.vm.jgnu.security.NoSuchProviderException, gnu.vm.jgnu.security.InvalidAlgorithmParameterException, IOException
	{
		if ((publicKey.getAuthentifiedSignatureAlgorithmType()!=null && !provider.equals(publicKey.getAuthentifiedSignatureAlgorithmType().getCodeProvider())) || (publicKey.getEncryptionAlgorithmType()!=null && !provider.equals(publicKey.getEncryptionAlgorithmType().getCodeProvider()))
				|| (keyToWrap.getAuthentifiedSignatureAlgorithmType()!=null && !provider.equals(keyToWrap.getAuthentifiedSignatureAlgorithmType().getCodeProvider())) || (keyToWrap.getEncryptionAlgorithmType()!=null && !provider.equals(keyToWrap.getEncryptionAlgorithmType().getCodeProvider())))
				throw new IllegalArgumentException("The keys must come from the same providers");
		
		if (provider.equals(CodeProvider.GNU_CRYPTO))
		{
			Cipher c = Cipher.getInstance(algorithmName);
			c.init(Cipher.WRAP_MODE, publicKey.toGnuKey());
			return c.wrap(keyToWrap.toGnuKey());
		}
		else
		{
			try
			{
				javax.crypto.Cipher c=null;
				if (provider.equals(CodeProvider.BCFIPS))
				{
					CodeProvider.ensureBouncyCastleProviderLoaded();
					c=javax.crypto.Cipher.getInstance(algorithmName, provider.name());
				}
				else
					c=javax.crypto.Cipher.getInstance(algorithmName);

				if (withParameters)
				{
					c.init(javax.crypto.Cipher.WRAP_MODE, publicKey.toJavaNativeKey(),
							new OAEPParameterSpec("SHA-384","MGF1",new MGF1ParameterSpec("SHA-384"),PSource.PSpecified.DEFAULT));
					byte[] wrapedKey=c.wrap(keyToWrap.toJavaNativeKey());
					byte[] encodedParameters=c.getParameters().getEncoded();
					return Bits.concateEncodingWithShortSizedTabs(wrapedKey, encodedParameters);
				}
				else if (this.algorithmName.equals(BC_FIPS_RSA_KTS_KTM.algorithmName))
				{
					c.init(javax.crypto.Cipher.WRAP_MODE, publicKey.toJavaNativeKey(), new KTSParameterSpec.Builder(NISTObjectIdentifiers.id_aes256_wrap.getId(),256).build());
					return c.wrap(keyToWrap.toJavaNativeKey());
				}
				else
				{
					c.init(javax.crypto.Cipher.WRAP_MODE, publicKey.toJavaNativeKey());
					return c.wrap(keyToWrap.toJavaNativeKey());
				}
				
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
	
	public SymmetricSecretKey unwrapKey(ASymmetricPrivateKey privateKey, byte[] keyToUnwrap, SymmetricAuthentifiedSignatureType signatureType, short keySize) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalStateException, gnu.vm.jgnu.security.NoSuchProviderException, InvalidKeySpecException, gnu.vm.jgnu.security.InvalidAlgorithmParameterException, IOException
	{
		return unwrapKey(privateKey, keyToUnwrap, null, signatureType, keySize);
	}
	public SymmetricSecretKey unwrapKey(ASymmetricPrivateKey privateKey, byte[] keyToUnwrap, SymmetricEncryptionType encryptionType, short keySize) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalStateException, gnu.vm.jgnu.security.NoSuchProviderException, InvalidKeySpecException, gnu.vm.jgnu.security.InvalidAlgorithmParameterException, IOException
	{
		return unwrapKey(privateKey, keyToUnwrap, encryptionType, null, keySize);
	}
	private SymmetricSecretKey unwrapKey(ASymmetricPrivateKey privateKey, byte[] keyToUnwrap, SymmetricEncryptionType encryptionType, SymmetricAuthentifiedSignatureType signatureType, short keySize) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalStateException, gnu.vm.jgnu.security.NoSuchProviderException, InvalidKeySpecException, IOException, gnu.vm.jgnu.security.InvalidAlgorithmParameterException
	{
		if ((privateKey.getAuthentifiedSignatureAlgorithmType()!=null && !provider.equals(privateKey.getAuthentifiedSignatureAlgorithmType().getCodeProvider())) || (privateKey.getEncryptionAlgorithmType()!=null && !provider.equals(privateKey.getEncryptionAlgorithmType().getCodeProvider()))
				|| (encryptionType!=null && !provider.equals(encryptionType.getCodeProvider())) || (signatureType!=null && !provider.equals(signatureType.getCodeProvider())))
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
				if (provider.equals(CodeProvider.BCFIPS))
				{
					CodeProvider.ensureBouncyCastleProviderLoaded();
					c=javax.crypto.Cipher.getInstance(algorithmName, provider.name());
				}
				else
					c=javax.crypto.Cipher.getInstance(algorithmName);
				byte[] wrapedKey=null;
				if (withParameters)
				{
					byte[][] tmp=Bits.separateEncodingsWithShortSizedTabs(keyToUnwrap);
					wrapedKey=tmp[0];
					AlgorithmParameters algorithmParameters = provider.equals(CodeProvider.BCFIPS)?AlgorithmParameters.getInstance("OAEP",provider.name()):AlgorithmParameters.getInstance("OAEP");
					algorithmParameters.init(tmp[1]);
					c.init(Cipher.UNWRAP_MODE, privateKey.toJavaNativeKey(), algorithmParameters);
				}
				else if (this.algorithmName.equals(BC_FIPS_RSA_KTS_KTM.algorithmName))
				{
					wrapedKey=keyToUnwrap;
					c.init(Cipher.UNWRAP_MODE, privateKey.toJavaNativeKey(), new KTSParameterSpec.Builder(NISTObjectIdentifiers.id_aes256_wrap.getId(),256).build());
				}
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

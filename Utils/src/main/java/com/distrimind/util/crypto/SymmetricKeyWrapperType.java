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

import java.security.NoSuchProviderException;

import gnu.vm.jgnu.security.InvalidKeyException;
import gnu.vm.jgnu.security.NoSuchAlgorithmException;
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
public enum SymmetricKeyWrapperType {

	BC_FIPS_AES("AESKW", CodeProvider.BCFIPS),
	BC_FIPS_AES_WITH_PADDING("AESKWP", CodeProvider.BCFIPS),
	DEFAULT(BC_FIPS_AES_WITH_PADDING);
	
	private final String algorithmName;
	private final CodeProvider provider;
	
	
	private SymmetricKeyWrapperType(String algorithmName, CodeProvider provider) {
		this.algorithmName = algorithmName;
		this.provider = provider;
	}
	
	private SymmetricKeyWrapperType(SymmetricKeyWrapperType other)
	{
		this(other.algorithmName, other.provider);
	}
	
	public CodeProvider getCodeProvider()
	{
		return provider;
	}
	public String getAlgorithmName()
	{
		return algorithmName;
	}
	
	public byte[] wrapKey(SymmetricSecretKey key, SymmetricSecretKey keyToWrap) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalStateException, IllegalBlockSizeException, gnu.vm.jgnu.security.NoSuchProviderException
	{
		if ((key.getAuthentifiedSignatureAlgorithmType()!=null && ((provider==CodeProvider.GNU_CRYPTO)!=(key.getAuthentifiedSignatureAlgorithmType().getCodeProviderForSignature()==CodeProvider.GNU_CRYPTO))) 
				|| (key.getEncryptionAlgorithmType()!=null  && ((provider==CodeProvider.GNU_CRYPTO)!=(key.getEncryptionAlgorithmType().getCodeProviderForEncryption()==CodeProvider.GNU_CRYPTO)))
				|| (keyToWrap.getAuthentifiedSignatureAlgorithmType()!=null && (provider==CodeProvider.GNU_CRYPTO)!=(keyToWrap.getAuthentifiedSignatureAlgorithmType().getCodeProviderForSignature()==CodeProvider.GNU_CRYPTO))
				|| (keyToWrap.getEncryptionAlgorithmType()!=null && (provider==CodeProvider.GNU_CRYPTO)!=(keyToWrap.getEncryptionAlgorithmType().getCodeProviderForEncryption()==CodeProvider.GNU_CRYPTO)))
				throw new IllegalArgumentException("The keys must come from the same providers");
		if (!algorithmName.startsWith(key.getEncryptionAlgorithmType().getAlgorithmName()))
			throw new IllegalArgumentException("The key must be compatible with algorithm "+algorithmName);
		if (provider.equals(CodeProvider.GNU_CRYPTO))
		{
			Cipher cipher=Cipher.getInstance(algorithmName);
			cipher.init(Cipher.WRAP_MODE, key.toGnuKey());
			return ASymmetricKeyWrapperType.wrapKeyWithMetaData(cipher.wrap(keyToWrap.toGnuKey()), keyToWrap);
		}
		else
		{
			try
			{
				javax.crypto.Cipher cipher=null;
				if (provider.equals(CodeProvider.BCFIPS))
				{
					CodeProvider.ensureBouncyCastleProviderLoaded();
					
				}
				cipher=javax.crypto.Cipher.getInstance(algorithmName, provider.checkProviderWithCurrentOS().name());

				cipher.init(javax.crypto.Cipher.WRAP_MODE, key.toJavaNativeKey());
				return ASymmetricKeyWrapperType.wrapKeyWithMetaData(cipher.wrap(keyToWrap.toJavaNativeKey()), keyToWrap);
				
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
			}
		}
	}
	public SymmetricSecretKey unwrapKey(SymmetricSecretKey key, byte[] keyToUnwrap) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalStateException, gnu.vm.jgnu.security.NoSuchProviderException
	{
		if (ASymmetricKeyWrapperType.isSignatureFromMetaData(keyToUnwrap))
			return unwrapKey(key, ASymmetricKeyWrapperType.getWrappedKeyFromMetaData(keyToUnwrap), null, ASymmetricKeyWrapperType.getSignatureTypeFromMetaData(keyToUnwrap), ASymmetricKeyWrapperType.getKeySizeFromMetaData(keyToUnwrap));
		else
			return unwrapKey(key, ASymmetricKeyWrapperType.getWrappedKeyFromMetaData(keyToUnwrap), ASymmetricKeyWrapperType.getEncryptionTypeFromMetaData(keyToUnwrap), null, ASymmetricKeyWrapperType.getKeySizeFromMetaData(keyToUnwrap));
	}
	private SymmetricSecretKey unwrapKey(SymmetricSecretKey key, byte[] keyToUnwrap, SymmetricEncryptionType encryptionType, SymmetricAuthentifiedSignatureType signatureType, short keySize) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalStateException, gnu.vm.jgnu.security.NoSuchProviderException
	{
		if ((key.getAuthentifiedSignatureAlgorithmType()!=null && ((provider==CodeProvider.GNU_CRYPTO)!=(key.getAuthentifiedSignatureAlgorithmType().getCodeProviderForSignature()==CodeProvider.GNU_CRYPTO))) 
				|| (key.getEncryptionAlgorithmType()!=null  && ((provider==CodeProvider.GNU_CRYPTO)!=(key.getEncryptionAlgorithmType().getCodeProviderForEncryption()==CodeProvider.GNU_CRYPTO)))
				|| (encryptionType!=null && (provider==CodeProvider.GNU_CRYPTO)!=(encryptionType.getCodeProviderForEncryption()==CodeProvider.GNU_CRYPTO))
				|| (signatureType!=null && (provider==CodeProvider.GNU_CRYPTO)!=(signatureType.getCodeProviderForSignature()==CodeProvider.GNU_CRYPTO)))
				throw new IllegalArgumentException("The keys must come from the same providers");
		
		if (provider.equals(CodeProvider.GNU_CRYPTO))
		{
			Cipher cipher=Cipher.getInstance(algorithmName);
			cipher.init(Cipher.UNWRAP_MODE, key.toGnuKey());
			if (encryptionType==null)
			{
				return new SymmetricSecretKey(signatureType, (SecretKey)cipher.unwrap(keyToUnwrap, signatureType.getAlgorithmName(), Cipher.SECRET_KEY), keySize);
			}
			else
				return new SymmetricSecretKey(encryptionType, (SecretKey)cipher.unwrap(keyToUnwrap, encryptionType.getAlgorithmName(), Cipher.SECRET_KEY), keySize);
		}
		else
		{
			try
			{
				javax.crypto.Cipher cipher=null;
				if (provider.equals(CodeProvider.BCFIPS))
				{
					CodeProvider.ensureBouncyCastleProviderLoaded();
					
				}
				cipher=javax.crypto.Cipher.getInstance(algorithmName, provider.checkProviderWithCurrentOS().name());


				cipher.init(Cipher.UNWRAP_MODE, key.toJavaNativeKey());
				if (encryptionType==null)
				{
					return new SymmetricSecretKey(signatureType, (javax.crypto.SecretKey)cipher.unwrap(keyToUnwrap, signatureType.getAlgorithmName(), javax.crypto.Cipher.SECRET_KEY), keySize);
				}
				else
					return new SymmetricSecretKey(encryptionType, (javax.crypto.SecretKey)cipher.unwrap(keyToUnwrap, encryptionType.getAlgorithmName(), javax.crypto.Cipher.SECRET_KEY), keySize);
				
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
			}
			
		}
	}
	
	
}

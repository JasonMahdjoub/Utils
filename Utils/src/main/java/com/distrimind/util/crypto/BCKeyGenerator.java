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

import com.distrimind.bcfips.crypto.SymmetricKeyGenerator;
import com.distrimind.bcfips.crypto.fips.FipsAES;
import com.distrimind.bcfips.crypto.general.AES;
import com.distrimind.bcfips.crypto.general.ChaCha20;
import com.distrimind.bcfips.crypto.general.Serpent;
import com.distrimind.bcfips.crypto.general.Twofish;

/**
 * 
 * @author Jason Mahdjoub
 * @version 2.1
 * @since Utils 3.10.0
 */
@SuppressWarnings("ConstantConditions")
public final class BCKeyGenerator extends AbstractKeyGenerator {

	private SymmetricKeyGenerator<com.distrimind.bcfips.crypto.SymmetricSecretKey> keyGenerator;
	private short keySizeBits;
	
	BCKeyGenerator(SymmetricAuthenticatedSignatureType type) {
		super(type);
	}
	
	BCKeyGenerator(SymmetricEncryptionType type) {
		super(type);
	}

	@Override
	public SymmetricSecretKey generateKey() {
		if (encryptionType==null)
			return new SymmetricSecretKey(signatureType, keyGenerator.generateKey(), keySizeBits);
		else
			return new SymmetricSecretKey(encryptionType, keyGenerator.generateKey(), keySizeBits);
	}

	@Override
	public String getAlgorithm() {
		
		if (encryptionType==null)
			return signatureType.getAlgorithmName();
		else
			return encryptionType.getAlgorithmName();
	}

	@Override
	public String getProvider() {
		if (encryptionType==null)
			return signatureType.getCodeProviderForKeyGenerator().getCompatibleCodeProviderName();
		else
			return encryptionType.getCodeProviderForKeyGenerator().getCompatibleCodeProviderName();
	}

	

	@SuppressWarnings("unchecked")
	@Override
	public void init(short keySize, AbstractSecureRandom random) {
		if (encryptionType==null)
		{
			if (signatureType.getCodeProviderForKeyGenerator().equals(CodeProvider.BC) || signatureType.getCodeProviderForKeyGenerator().equals(CodeProvider.BCFIPS))
			{
				keyGenerator=new FipsAES.KeyGenerator(FipsAES.CBCwithPKCS7, keySize, random);
				this.keySizeBits=keySize;
			}
			else
				throw new IllegalAccessError();
			
		}
		else
		{
			if (encryptionType.equals(SymmetricEncryptionType.BC_CHACHA20_NO_RANDOM_ACCESS) || encryptionType.equals(SymmetricEncryptionType.BC_CHACHA20_POLY1305)) {
				if (keySize!=256)
					throw new IllegalAccessError("Key size must be equal to 256 with BouncyCastle ChaCha20");
				keyGenerator=new ChaCha20.KeyGenerator(random);
				this.keySizeBits=keySize;
			}
			else if (encryptionType.equals(SymmetricEncryptionType.BC_FIPS_AES_GCM)
					&& SymmetricEncryptionType.BC_FIPS_AES_GCM.getBlockMode().equals(encryptionType.getBlockMode()))
			{
				keyGenerator=new FipsAES.KeyGenerator(FipsAES.GCM, keySize, random);
				this.keySizeBits=keySize;
			}
			else if (encryptionType.equals(SymmetricEncryptionType.BC_FIPS_AES_CTR)
					&& SymmetricEncryptionType.BC_FIPS_AES_CTR.getBlockMode().equals(encryptionType.getBlockMode()))
			{
				keyGenerator=new FipsAES.KeyGenerator(FipsAES.CTR, keySize, random);
				this.keySizeBits=keySize;
			}
			else if (encryptionType.equals(SymmetricEncryptionType.BC_FIPS_AES_CBC_PKCS7Padding)
					&& SymmetricEncryptionType.BC_FIPS_AES_CBC_PKCS7Padding.getBlockMode().equals(encryptionType.getBlockMode()))
			{
				keyGenerator=new FipsAES.KeyGenerator(FipsAES.CBCwithPKCS7, keySize, random);
				this.keySizeBits=keySize;
			}
			else if (encryptionType.equals(SymmetricEncryptionType.BC_AES_EAX)
					&& SymmetricEncryptionType.BC_AES_EAX.getBlockMode().equals(encryptionType.getBlockMode()))
			{
				keyGenerator=new AES.KeyGenerator(AES.EAX, keySize, random);
				this.keySizeBits=keySize;
			}
			else if (encryptionType.equals(SymmetricEncryptionType.BC_SERPENT_CBC_PKCS7Padding)
					&& SymmetricEncryptionType.BC_SERPENT_CBC_PKCS7Padding.getBlockMode().equals(encryptionType.getBlockMode()))
			{
				keyGenerator=new Serpent.KeyGenerator(Serpent.CBCwithPKCS7, keySize, random);
				this.keySizeBits=keySize;
			}
			else if (encryptionType.equals(SymmetricEncryptionType.BC_SERPENT_CTR)
					&& SymmetricEncryptionType.BC_SERPENT_CTR.getBlockMode().equals(encryptionType.getBlockMode()))
			{
				keyGenerator=new Serpent.KeyGenerator(Serpent.CTR, keySize, random);
				this.keySizeBits=keySize;
			}
			else if (encryptionType.equals(SymmetricEncryptionType.BC_SERPENT_GCM)
					&& SymmetricEncryptionType.BC_SERPENT_GCM.getBlockMode().equals(encryptionType.getBlockMode()))
			{
				keyGenerator=new Serpent.KeyGenerator(Serpent.GCM, keySize, random);
				this.keySizeBits=keySize;
			}
			else if (encryptionType.equals(SymmetricEncryptionType.BC_SERPENT_EAX)
					&& SymmetricEncryptionType.BC_SERPENT_EAX.getBlockMode().equals(encryptionType.getBlockMode()))
			{
				keyGenerator=new Serpent.KeyGenerator(Serpent.EAX, keySize, random);
				this.keySizeBits=keySize;
			}
			else if (encryptionType.equals(SymmetricEncryptionType.BC_TWOFISH_CBC_PKCS7Padding)
					&& SymmetricEncryptionType.BC_TWOFISH_CBC_PKCS7Padding.getBlockMode().equals(encryptionType.getBlockMode()))
			{
				keyGenerator=new Twofish.KeyGenerator(Twofish.CBCwithPKCS7, keySize, random);
				this.keySizeBits=keySize;
			}
			else if (encryptionType.equals(SymmetricEncryptionType.BC_TWOFISH_CTR)
					&& SymmetricEncryptionType.BC_TWOFISH_CTR.getBlockMode().equals(encryptionType.getBlockMode()))
			{
				keyGenerator=new Twofish.KeyGenerator(Twofish.CTR, keySize, random);
				this.keySizeBits=keySize;
			}
			else if (encryptionType.equals(SymmetricEncryptionType.BC_TWOFISH_GCM)
					&& SymmetricEncryptionType.BC_TWOFISH_GCM.getBlockMode().equals(encryptionType.getBlockMode()))
			{
				keyGenerator=new Twofish.KeyGenerator(Twofish.GCM, keySize, random);
				this.keySizeBits=keySize;
			}
			else if (encryptionType.equals(SymmetricEncryptionType.BC_TWOFISH_EAX)
					&& SymmetricEncryptionType.BC_TWOFISH_EAX.getBlockMode().equals(encryptionType.getBlockMode()))
			{
				keyGenerator=new Twofish.KeyGenerator(Twofish.EAX, keySize, random);
				this.keySizeBits=keySize;
			}
			else
				throw new IllegalAccessError();

		}
		
	}

}

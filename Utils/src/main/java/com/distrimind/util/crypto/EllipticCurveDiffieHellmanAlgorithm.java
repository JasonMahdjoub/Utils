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
import java.util.Arrays;

import org.bouncycastle.jcajce.spec.UserKeyingMaterialSpec;

import gnu.vm.jgnu.security.InvalidAlgorithmParameterException;

/**
 * 
 * @author Jason Mahdjoub
 * @version 2.2
 * @since Utils 2.9
 */
public class EllipticCurveDiffieHellmanAlgorithm {
	private final EllipticCurveDiffieHellmanType type;
	private SymmetricSecretKey derivedKey;
	private ASymmetricKeyPair myKeyPair;
	private byte[] myPublicKeyBytes;
	private final AbstractSecureRandom randomForKeys;

	EllipticCurveDiffieHellmanAlgorithm(AbstractSecureRandom randomForKeys, EllipticCurveDiffieHellmanType type) {
		if (type == null)
			throw new NullPointerException();
		if (randomForKeys == null)
			throw new NullPointerException();
		this.type = type;
		this.randomForKeys=randomForKeys;
		reset();
	}

	public void zeroize()
	{
		if (derivedKey!=null)
		{
			derivedKey=null;
		}
		if (myKeyPair!=null)
		{
			myKeyPair=null;
		}
		if (myPublicKeyBytes!=null)
		{
			Arrays.fill(myPublicKeyBytes, (byte)0);
			myPublicKeyBytes=null;
		}
		
	}
	
	@Override
	public void finalize()
	{
		zeroize();
	}
	
	public void reset() {
		derivedKey = null;
		myKeyPair = null;
		myPublicKeyBytes = null;
	}
	public ASymmetricKeyPair generateAndSetKeyPair() throws gnu.vm.jgnu.security.NoSuchAlgorithmException, gnu.vm.jgnu.security.spec.InvalidKeySpecException, gnu.vm.jgnu.security.NoSuchProviderException, InvalidAlgorithmParameterException  {
		return generateAndSetKeyPair(type.getECDHKeySizeBits(), System.currentTimeMillis()+(24*60*60*1000));
	}
	public ASymmetricKeyPair generateAndSetKeyPair(short keySize) throws gnu.vm.jgnu.security.NoSuchAlgorithmException, gnu.vm.jgnu.security.spec.InvalidKeySpecException, gnu.vm.jgnu.security.NoSuchProviderException, InvalidAlgorithmParameterException  {
		return generateAndSetKeyPair(keySize, System.currentTimeMillis()+(24*60*60*1000));
	}
	public ASymmetricKeyPair generateAndSetKeyPair(short keySize, long expirationUTC) throws gnu.vm.jgnu.security.NoSuchAlgorithmException, gnu.vm.jgnu.security.spec.InvalidKeySpecException, gnu.vm.jgnu.security.NoSuchProviderException, InvalidAlgorithmParameterException  {
		ASymmetricKeyPair kp=type.getASymmetricAuthentifiedSignatureType().getKeyPairGenerator(randomForKeys, keySize, expirationUTC).generateKeyPair();
		setKeyPair(kp);

		return myKeyPair;
	}
	
	public void setKeyPair(ASymmetricKeyPair keyPair) throws gnu.vm.jgnu.security.NoSuchAlgorithmException, gnu.vm.jgnu.security.spec.InvalidKeySpecException
	{
		if (keyPair==null)
			throw new NullPointerException("keyPair");
		reset();
		myKeyPair = keyPair;
		myPublicKeyBytes = myKeyPair.getASymmetricPublicKey().encode();
	}
	
	public ASymmetricKeyPair getKeyPair()
	{
		return myKeyPair;
	}
	
	public byte[] getEncodedPublicKey()
	{
		return myPublicKeyBytes;
	}

	public void setDistantPublicKey(byte[] distantPublicKeyBytes, SymmetricEncryptionType symmetricEncryptionType, short keySize, byte[] keyingMaterial) throws 
	gnu.vm.jgnu.security.NoSuchAlgorithmException, gnu.vm.jgnu.security.InvalidKeyException, gnu.vm.jgnu.security.spec.InvalidKeySpecException, gnu.vm.jgnu.security.NoSuchProviderException, InvalidAlgorithmParameterException {
		setDistantPublicKey(distantPublicKeyBytes, symmetricEncryptionType, null, keySize, keyingMaterial);
	}
	public void setDistantPublicKey(byte[] distantPublicKeyBytes, SymmetricAuthentifiedSignatureType symmetricSignatureType, short keySize, byte[] keyingMaterial) throws 
	gnu.vm.jgnu.security.NoSuchAlgorithmException, gnu.vm.jgnu.security.InvalidKeyException, gnu.vm.jgnu.security.spec.InvalidKeySpecException, gnu.vm.jgnu.security.NoSuchProviderException, InvalidAlgorithmParameterException {
		setDistantPublicKey(distantPublicKeyBytes, null, symmetricSignatureType, keySize, keyingMaterial);
	}
	private void setDistantPublicKey(byte[] distantPublicKeyBytes, SymmetricEncryptionType symmetricEncryptionType, SymmetricAuthentifiedSignatureType symmetricSignatureType, short keySize, byte[] keyingMaterial) throws 
			gnu.vm.jgnu.security.NoSuchAlgorithmException, gnu.vm.jgnu.security.InvalidKeyException, gnu.vm.jgnu.security.spec.InvalidKeySpecException, gnu.vm.jgnu.security.NoSuchProviderException, InvalidAlgorithmParameterException {
		try
		{
			if (distantPublicKeyBytes == null)
				throw new NullPointerException();
			if (keyingMaterial==null)
				throw new NullPointerException();
			if (keyingMaterial.length==0)
				throw new IllegalArgumentException();
			if (derivedKey != null)
				throw new IllegalArgumentException(
						"A key exchange process has already been begun. Use reset fonction before calling this function.");
			if (type.getCodeProvider() == CodeProvider.BCFIPS || type.getCodeProvider() == CodeProvider.BC) {
				CodeProvider.ensureBouncyCastleProviderLoaded();
				
			} 
			ASymmetricPublicKey distantPublicKey=(ASymmetricPublicKey)Key.decode(distantPublicKeyBytes);
			if (myKeyPair.getASymmetricPublicKey().equals(distantPublicKey))
				throw new gnu.vm.jgnu.security.InvalidKeyException("The local et distant public keys cannot be similar !");
	
			AbstractKeyAgreement ka = null;
			if (symmetricEncryptionType==null)
				ka = type.getKeyAgreementInstance(symmetricSignatureType);
			else
				ka = type.getKeyAgreementInstance(symmetricEncryptionType);
	
			ka.init(myKeyPair.getASymmetricPrivateKey(), new UserKeyingMaterialSpec(keyingMaterial));
			ka.doPhase(distantPublicKey, true);
			derivedKey=ka.generateSecretKey((short)(type.getKeySizeBits()/8));
		}
		catch(NoSuchAlgorithmException e)
		{
			throw new gnu.vm.jgnu.security.NoSuchAlgorithmException(e);
		}
		catch (NoSuchProviderException e) {
			throw new gnu.vm.jgnu.security.NoSuchAlgorithmException(e.getMessage());
		}		
	}

	public SymmetricSecretKey getDerivedKey() {
		return derivedKey;
	}

}

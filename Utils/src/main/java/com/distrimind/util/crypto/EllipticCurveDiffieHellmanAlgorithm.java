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

import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.jcajce.spec.UserKeyingMaterialSpec;

/**
 * 
 * @author Jason Mahdjoub
 * @version 3.0
 * @since Utils 2.9
 */
public class EllipticCurveDiffieHellmanAlgorithm extends KeyAgreement {
	private final EllipticCurveDiffieHellmanType type;
	private SymmetricSecretKey derivedKey;
	private ASymmetricKeyPair myKeyPair;
	private byte[] myPublicKeyBytes;
	private final AbstractSecureRandom randomForKeys;
	private boolean valid=true;
	private SymmetricEncryptionType encryptionType;
	private SymmetricAuthentifiedSignatureType signatureType;
	private final short keySizeBits;

	@Override
	public boolean isPostQuantumAgreement() {
		return type.isPostQuantumAlgorithm();
	}


	private byte[] keyingMaterial;
	EllipticCurveDiffieHellmanAlgorithm(AbstractSecureRandom randomForKeys, EllipticCurveDiffieHellmanType type, short keySizeBits, byte[] keyingMaterial, SymmetricAuthentifiedSignatureType signatureType) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
		this(randomForKeys, type, keySizeBits, keyingMaterial);
		this.signatureType=signatureType;
	}
	EllipticCurveDiffieHellmanAlgorithm(AbstractSecureRandom randomForKeys, EllipticCurveDiffieHellmanType type, short keySizeBits, byte[] keyingMaterial, SymmetricEncryptionType encryptionType) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
		this(randomForKeys, type, keySizeBits, keyingMaterial);
		this.encryptionType=encryptionType;
	}
	private EllipticCurveDiffieHellmanAlgorithm(AbstractSecureRandom randomForKeys, EllipticCurveDiffieHellmanType type, short keySizeBits, byte[] keyingMaterial) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
		super(1, 1);
		if (type == null)
			throw new NullPointerException();
		if (randomForKeys == null)
			throw new NullPointerException();
		this.type = type;
		this.randomForKeys=randomForKeys;
		
		this.keyingMaterial=keyingMaterial;
		this.keySizeBits=keySizeBits;
		reset();
		generateAndSetKeyPair();
	}

	public void zeroize()
	{
		derivedKey=null;
		myKeyPair=null;
		if (myPublicKeyBytes!=null)
		{
			Arrays.fill(myPublicKeyBytes, (byte)0);
			myPublicKeyBytes=null;
		}
		
	}



	public void reset() {
		derivedKey = null;
		myKeyPair = null;
		myPublicKeyBytes = null;
	}
	private void generateAndSetKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException  {
		generateAndSetKeyPair(type.getECDHKeySizeBits(), System.currentTimeMillis()+(24*60*60*1000));
	}
	/*private ASymmetricKeyPair generateAndSetKeyPair(short keySize) throws NoSuchAlgorithmException, spec.InvalidKeySpecException, NoSuchProviderException, InvalidAlgorithmParameterException  {
		return generateAndSetKeyPair(keySize, System.currentTimeMillis()+(24*60*60*1000));
	}¨*/
	private void generateAndSetKeyPair(short keySize, long expirationUTC) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException  {
		valid=false;

		ASymmetricKeyPair kp;
		ASymmetricAuthenticatedSignatureType t=type.getASymmetricAuthentifiedSignatureType();
		if (t== ASymmetricAuthenticatedSignatureType.BC_Ed448 || t== ASymmetricAuthenticatedSignatureType.BC_Ed25519) {
			try {
				KeyPairGenerator kpg ;
				if (t== ASymmetricAuthenticatedSignatureType.BC_Ed448)
					kpg= KeyPairGenerator.getInstance("X448", CodeProvider.BC.name());
				else
					kpg= KeyPairGenerator.getInstance("X25519", CodeProvider.BC.name());

				JavaNativeKeyPairGenerator res = new JavaNativeKeyPairGenerator(t, kpg);
				res.initialize(keySize, expirationUTC, randomForKeys);
				kp=res.generateKeyPair();
			} catch (NoSuchAlgorithmException e) {
				throw new NoSuchAlgorithmException(e);
			}
			catch(java.security.NoSuchProviderException e)
			{
				throw new NoSuchProviderException(e.getMessage());
			}

		}
		else
			kp=t.getKeyPairGenerator(randomForKeys, keySize, expirationUTC).generateKeyPair();
		setKeyPair(kp);
		valid=true;

	}
	
	private void setKeyPair(ASymmetricKeyPair keyPair)
	{
		if (keyPair==null)
			throw new NullPointerException("keyPair");
		reset();
		myKeyPair = keyPair;
		myPublicKeyBytes = myKeyPair.getASymmetricPublicKey().encode(true);
	}
	
	/*private ASymmetricKeyPair getKeyPair()
	{
		return myKeyPair;
	}*/
	
	private byte[] getEncodedPublicKey()
	{
		return myPublicKeyBytes;
	}

	private void setDistantPublicKey(byte[] distantPublicKeyBytes, SymmetricEncryptionType symmetricEncryptionType, SymmetricAuthentifiedSignatureType symmetricSignatureType, byte[] keyingMaterial) throws 
			NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException, InvalidAlgorithmParameterException {
		CodeProvider.encureProviderLoaded(type.getCodeProvider());
		try
		{
			valid=false;
			if (distantPublicKeyBytes == null)
				throw new NullPointerException();
			if (keyingMaterial==null)
				throw new NullPointerException();
			if (keyingMaterial.length==0)
				throw new IllegalArgumentException();
			if (derivedKey != null)
				throw new IllegalArgumentException(
						"A key exchange process has already been begun. Use reset fonction before calling this function.");
			ASymmetricPublicKey distantPublicKey=(ASymmetricPublicKey) AbstractKey.decode(distantPublicKeyBytes);
			if (myKeyPair.getASymmetricPublicKey().equals(distantPublicKey))
				throw new InvalidKeyException("The local et distant public keys cannot be similar !");
	
			AbstractKeyAgreement ka ;
			if (symmetricEncryptionType==null)
				ka = type.getKeyAgreementInstance(symmetricSignatureType);
			else
				ka = type.getKeyAgreementInstance(symmetricEncryptionType);
			if (type.isECCDHType() || type.isXDHType()) {

				UserKeyingMaterialSpec spec=null;
				if (type.useKDF())
					spec=new UserKeyingMaterialSpec(keyingMaterial);
				ka.init(myKeyPair.getASymmetricPrivateKey(), spec, randomForKeys);
			}
			else if (type.isECMQVType())
			{
				throw new InternalError("Next code must use ephemeral and static keys. It must be completed/corrected.");
				/*ka.init(myKeyPair.getASymmetricPrivateKey(), new Object[] {
						FipsEC.MQV.using(
								(AsymmetricECPublicKey)myKeyPair.getASymmetricPublicKey().toBouncyCastleKey(), (AsymmetricECPrivateKey)myKeyPair.getASymmetricPrivateKey().toBouncyCastleKey(), (AsymmetricECPublicKey)distantPublicKey.toBouncyCastleKey()),
						keyingMaterial,
					}
				);*/
			}
			ka.doPhase(distantPublicKey, true);
			if (ka instanceof JavaNativeKeyAgreement)
				derivedKey=ka.generateSecretKey(keySizeBits);
			else
				derivedKey=ka.generateSecretKey((short)(keySizeBits/8));
			valid=true;
		}
		catch(NoSuchAlgorithmException e)
		{
			throw new NoSuchAlgorithmException(e);
		}
		catch (NoSuchProviderException e) {
			throw new NoSuchAlgorithmException(e.getMessage());
		}		
	}

	public SymmetricSecretKey getDerivedKey() {
		return derivedKey;
	}

	@Override
	public short getDerivedKeySizeBytes() {
		return (short)(keySizeBits/8);
	}

	@Override
	protected boolean isAgreementProcessValidImpl() {
		return valid;
	}

	@Override
	protected byte[] getDataToSend(int stepNumber) throws Exception {
		if (!valid)
			throw new CryptoException();

		if (stepNumber == 0)
			return getEncodedPublicKey();
		else {
			valid = false;
			throw new IllegalAccessException();
		}

	}

	@Override
	protected void receiveData(int stepNumber, byte[] data) throws CryptoException {
		if (!valid)
			throw new CryptoException();

		try {
			if (stepNumber == 0) {
				setDistantPublicKey(data, encryptionType, signatureType, keyingMaterial);
			} else
				throw new IllegalAccessException();
		}
		catch(Exception e)
		{
			valid=false;
			throw new CryptoException("", e);
		}
	}

}

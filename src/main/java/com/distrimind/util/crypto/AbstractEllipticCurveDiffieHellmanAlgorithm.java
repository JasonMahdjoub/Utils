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

import com.distrimind.bouncycastle.crypto.CryptoException;
import com.distrimind.bouncycastle.jcajce.spec.UserKeyingMaterialSpec;
import com.distrimind.util.Cleanable;
import com.distrimind.util.data_buffers.WrappedData;
import com.distrimind.util.io.Integrity;
import com.distrimind.util.io.MessageExternalizationException;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

/**
 *
 * @author Jason Mahdjoub
 * @version 3.0
 * @since Utils 2.9
 */
public abstract class AbstractEllipticCurveDiffieHellmanAlgorithm extends Agreement {
	private static final class Finalizer extends Cleaner
	{
		private SymmetricSecretKey derivedKey;
		private SymmetricSecretKeyPair derivedKeyPair;
		private ASymmetricKeyPair myKeyPair;

		private Finalizer(Cleanable cleanable) {
			super(cleanable);
		}

		@Override
		protected void performCleanup() {
			if (derivedKey!=null)
			{
				derivedKey=null;
			}
			if (derivedKeyPair!=null)
			{
				derivedKeyPair=null;
			}
			if (myKeyPair!=null)
			{
				myKeyPair.clean();
				myKeyPair=null;
			}
		}
	}
	private final Finalizer finalizer;
	private final EllipticCurveDiffieHellmanType type;

	private WrappedData myPublicKeyBytes;
	private final AbstractSecureRandom randomForKeys;
	private boolean valid=true;
	private final SymmetricEncryptionType encryptionType;
	private final SymmetricAuthenticatedSignatureType signatureType;
	private final short keySizeBits;

	@Override
	public boolean isPostQuantumAgreement() {
		return type.isPostQuantumAlgorithm();
	}


	private final byte[] keyingMaterial;
	protected AbstractEllipticCurveDiffieHellmanAlgorithm(AbstractSecureRandom randomForKeys, EllipticCurveDiffieHellmanType type, short keySizeBits, byte[] keyingMaterial, SymmetricAuthenticatedSignatureType signatureType, SymmetricEncryptionType encryptionType) throws NoSuchAlgorithmException, NoSuchProviderException, IOException {
		super(1, 1);
		if (type == null)
			throw new NullPointerException();
		if (randomForKeys == null)
			throw new NullPointerException();
		if (encryptionType==null && signatureType==null)
			throw new NullPointerException();
		if (this instanceof IDualKeyAgreement)
		{
			if (encryptionType==null)
				throw new NullPointerException();
			if (signatureType==null)
				throw new NullPointerException();
		}
		this.signatureType=signatureType;
		this.encryptionType=encryptionType;
		this.finalizer=new Finalizer(this);
		this.type = type;
		this.randomForKeys=randomForKeys;

		this.keyingMaterial=keyingMaterial;
		this.keySizeBits=keySizeBits;

		reset();
		generateAndSetKeyPair();
	}



	public void reset() {
		finalizer.performCleanup();
		myPublicKeyBytes = null;
	}
	private void generateAndSetKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException, IOException {
		generateAndSetKeyPair(type.getECDHKeySizeBits());
	}
	/*private ASymmetricKeyPair generateAndSetKeyPair(short keySize) throws NoSuchAlgorithmException, spec.InvalidKeySpecException, NoSuchProviderException, InvalidAlgorithmParameterException  {
		return generateAndSetKeyPair(keySize, System.currentTimeMillis()+(24*60*60*1000));
	}¨*/
	private void generateAndSetKeyPair(short keySize) throws NoSuchAlgorithmException, NoSuchProviderException, IOException  {
		valid=false;

		ASymmetricKeyPair kp;
		ASymmetricAuthenticatedSignatureType t=type.getASymmetricAuthenticatedSignatureType();
		if (t== ASymmetricAuthenticatedSignatureType.BC_FIPS_Ed448 || t== ASymmetricAuthenticatedSignatureType.BC_FIPS_Ed25519) {
			KeyPairGenerator kpg ;
			if (t== ASymmetricAuthenticatedSignatureType.BC_FIPS_Ed448)
				kpg= KeyPairGenerator.getInstance("X448", CodeProvider.BCFIPS.getCompatibleProvider());
			else
				kpg= KeyPairGenerator.getInstance("X25519", CodeProvider.BCFIPS.getCompatibleProvider());

			JavaNativeKeyPairGenerator res = new JavaNativeKeyPairGenerator(type, kpg);
			res.initialize(keySize, System.currentTimeMillis(), Long.MAX_VALUE, randomForKeys);
			kp=res.generateKeyPair();

		}
		else
			kp=t.getKeyPairGenerator(randomForKeys, keySize, System.currentTimeMillis(),Long.MAX_VALUE).generateKeyPair();
		setKeyPair(kp);
		valid=true;

	}

	private void setKeyPair(ASymmetricKeyPair keyPair)
	{
		if (keyPair==null)
			throw new NullPointerException("keyPair");
		reset();
		finalizer.myKeyPair = keyPair;
		myPublicKeyBytes = finalizer.myKeyPair.getASymmetricPublicKey().encode();
	}


	private WrappedData getEncodedPublicKey()
	{
		return myPublicKeyBytes;
	}

	private void setDistantPublicKey(byte[] distantPublicKeyBytes, SymmetricEncryptionType symmetricEncryptionType, SymmetricAuthenticatedSignatureType symmetricSignatureType, byte[] keyingMaterial) throws IOException {
		//CodeProvider.ensureProviderLoaded(type.getCodeProvider());
		try
		{
			valid=false;
			if (distantPublicKeyBytes == null)
				throw new NullPointerException();
			if (keyingMaterial==null)
				throw new NullPointerException();
			if (keyingMaterial.length==0)
				throw new IllegalArgumentException();
			if (finalizer.derivedKey != null)
				throw new IllegalArgumentException(
						"A key exchange process has already been begun. Use reset function before calling this function.");
			ASymmetricPublicKey distantPublicKey=(ASymmetricPublicKey) AbstractKey.decode(distantPublicKeyBytes);
			if (finalizer.myKeyPair.getASymmetricPublicKey().equals(distantPublicKey))
				throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN, new InvalidKeyException("The local et distant public keys cannot be similar !"));

			AbstractKeyAgreement ka ;
			if (symmetricEncryptionType==null)
				ka = type.getKeyAgreementInstance(symmetricSignatureType);
			else
				ka = type.getKeyAgreementInstance(symmetricEncryptionType);
			if (type.isECCDHType())
			{
				UserKeyingMaterialSpec spec=null;
				if (type.useKDF())
					spec=new UserKeyingMaterialSpec(keyingMaterial);
				ka.init(finalizer.myKeyPair.getASymmetricPrivateKey(), spec, randomForKeys);

			}
			else if (type.isXDHType()) {
				ka.init(finalizer.myKeyPair.getASymmetricPrivateKey(), null, randomForKeys);
			}
			else if (type.isECMQVType())
			{
				throw new InternalError("Next code must use ephemeral and static keys. It must be completed/corrected.");
			}
			else
				throw new InternalError(type.name());
			ka.doPhase(distantPublicKey, true);
			if (ka instanceof JavaNativeKeyAgreement)
				finalizer.derivedKey=ka.generateSecretKey(keySizeBits);
			else
				finalizer.derivedKey=ka.generateSecretKey((short)(keySizeBits/8));
			if (symmetricEncryptionType!=null && symmetricSignatureType!=null)
			{
				finalizer.derivedKeyPair=finalizer.derivedKey.getDerivedSecretKeyPair(MessageDigestType.BC_FIPS_SHA3_512, symmetricSignatureType);
			}
			valid=true;
		}
		catch (NoSuchAlgorithmException | NoSuchProviderException e) {
			throw new IOException(e);
		}
	}

	protected SymmetricSecretKey getDerivedKey() {
		return finalizer.derivedKey;
	}
	protected SymmetricSecretKeyPair getDerivedSecretKeyPair()
	{
		return finalizer.derivedKeyPair;
	}

	public short getDerivedKeySizeBytes() {
		return (short)(keySizeBits/8);
	}


	@Override
	public boolean isAgreementProcessValidImpl() {
		return valid;
	}

	@Override
	protected byte[] getDataToSend(int stepNumber) throws IOException {
		if (!valid)
			throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN, new CryptoException());

		if (stepNumber == 0)
			return getEncodedPublicKey().getBytes().clone();
		else {
			valid = false;
			throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN, new IllegalAccessException());
		}

	}

	@Override
	protected void receiveData(int stepNumber, byte[] data) throws MessageExternalizationException {
		if (!valid)
			throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN, new CryptoException());

		try {
			if (stepNumber == 0) {
				setDistantPublicKey(data, encryptionType, signatureType, keyingMaterial);
			} else
				throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN, new IllegalAccessException());
		}
		catch(Exception e)
		{
			valid=false;
			throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN, new CryptoException());
		}
	}

}

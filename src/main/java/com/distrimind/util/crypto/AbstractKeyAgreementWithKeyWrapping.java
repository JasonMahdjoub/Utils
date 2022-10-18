package com.distrimind.util.crypto;
/*
Copyright or © or Copr. Jason Mahdjoub (01/04/2013)

jason.mahdjoub@distri-mind.fr

This software (Object Oriented Database (OOD)) is a computer program 
whose purpose is to manage a local database with the object paradigm 
and the java language 

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

import com.distrimind.util.io.*;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

/**
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 5.24.0
 */
public abstract class AbstractKeyAgreementWithKeyWrapping<PubKey extends IASymmetricPublicKey, PrivKey extends IASymmetricPrivateKey, KP extends AbstractKeyPair<PrivKey, PubKey>> extends Agreement{
	private final KP myKeyPairForEncryption, myKeyPairForSignature;
	private PubKey otherPublicKeyForEncryption =null, otherPublicKeyForSignature=null;

	private final int keySizeBits;
	private final SymmetricSecretKey mySecretKey, mySecretKeyForSignature;
	private SymmetricSecretKey generatedSecretKey, generatedSecretKeyForSignature;
	private final ASymmetricKeyWrapperType aSymmetricKeyWrapperType;
	private final AbstractSecureRandom random;
	private boolean valid=true;





	@SuppressWarnings({"ConstantConditions", "ConditionCoveredByFurtherCondition"})
	protected AbstractKeyAgreementWithKeyWrapping(AbstractSecureRandom random, ASymmetricKeyWrapperType aSymmetricKeyWrapperType, KP keyPairForEncryption, KP keyPairForSignature, short keySizeBits, SymmetricAuthenticatedSignatureType signatureType, SymmetricEncryptionType encryptionType) throws NoSuchAlgorithmException, NoSuchProviderException{
		super(2, 2);
		if (keyPairForEncryption==null)
			throw new NullPointerException();
		if (keyPairForSignature==null)
			throw new NullPointerException();
		if (keyPairForEncryption.isPostQuantumKey()!=keyPairForSignature.isPostQuantumKey())
			throw new IllegalArgumentException();
		if (!keyPairForEncryption.useEncryptionAlgorithm())
			throw new IllegalArgumentException();
		if (!keyPairForSignature.useAuthenticatedSignatureAlgorithm())
			throw new IllegalArgumentException();

		if (signatureType==null && encryptionType==null)
			throw new NullPointerException();
		if (keySizeBits<56)
			throw new IllegalArgumentException();
		if (keySizeBits>SymmetricEncryptionType.MAX_SYMMETRIC_KEY_SIZE*8 && keySizeBits>SymmetricAuthenticatedSignatureType.MAX_SYMMETRIC_KEY_SIZE*8)
			throw new IllegalArgumentException();
		if (aSymmetricKeyWrapperType==null)
			throw new NullPointerException();
		if (random==null)
			throw new NullPointerException();
		this.myKeyPairForEncryption =keyPairForEncryption;
		this.myKeyPairForSignature =keyPairForSignature;
		this.keySizeBits=keySizeBits;
		this.aSymmetricKeyWrapperType=aSymmetricKeyWrapperType;
		this.random=random;
		if (encryptionType!=null) {
			mySecretKey = encryptionType.getKeyGenerator(random, keySizeBits).generateKey();
			if (signatureType != null)
				mySecretKeyForSignature = signatureType.getKeyGenerator(random, keySizeBits).generateKey();
			else
				mySecretKeyForSignature=null;
		}
		else {
			mySecretKey = signatureType.getKeyGenerator(random, keySizeBits).generateKey();
			mySecretKeyForSignature=null;
		}

	}

	@Override
	public boolean isAgreementProcessValidImpl() {
		return valid;
	}

	@Override
	protected byte[] getDataToSend(int stepNumber) throws IOException {
		try {

			switch (stepNumber) {
				case 0:
					try(RandomByteArrayOutputStream out=new RandomByteArrayOutputStream())
					{
						out.writeObject(myKeyPairForSignature.getASymmetricPublicKey(), false);

						EncryptionSignatureHashEncoder encoder=new EncryptionSignatureHashEncoder()
								.withASymmetricPrivateKeyForSignature(myKeyPairForSignature.getASymmetricPrivateKey());
						try(RandomOutputStream encOut=encoder.getRandomOutputStream(new LimitedRandomOutputStream(out, out.currentPosition())))
						{
							encOut.writeObject(myKeyPairForEncryption.getASymmetricPublicKey(), false);
						}
						out.flush();
						return out.getBytes();
					}
				case 1:
					try(RandomByteArrayOutputStream out=new RandomByteArrayOutputStream()) {
						try (KeyWrapperAlgorithm kw = new KeyWrapperAlgorithm(aSymmetricKeyWrapperType, otherPublicKeyForEncryption, myKeyPairForSignature.getASymmetricPrivateKey())) {
							out.writeWrappedData(kw.wrap(random, mySecretKey), false);
						}
						if (mySecretKeyForSignature!=null)
						{
							try (KeyWrapperAlgorithm kw = new KeyWrapperAlgorithm(aSymmetricKeyWrapperType, otherPublicKeyForEncryption, myKeyPairForSignature.getASymmetricPrivateKey())) {
								out.writeWrappedData(kw.wrap(random, mySecretKeyForSignature), false);
							}
						}
						out.flush();
						return out.getBytes();
					}
				default:
					throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN);
			}

		}
		catch (IOException e)
		{
			valid=false;
			throw e;
		}

	}

	@Override
	protected void receiveData(int stepNumber, byte[] data) throws IOException {
		try {
			switch (stepNumber) {
				case 0:
					try(RandomByteArrayInputStream in=new RandomByteArrayInputStream(data))
					{
						otherPublicKeyForSignature=in.readObject(false);
						if (otherPublicKeyForSignature.isPostQuantumKey()!=myKeyPairForSignature.isPostQuantumKey()) {
							otherPublicKeyForSignature=null;
							throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN);
						}
						if (!otherPublicKeyForSignature.useAuthenticatedSignatureAlgorithm()) {
							otherPublicKeyForSignature=null;
							throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN);
						}
						EncryptionSignatureHashDecoder decoder=new EncryptionSignatureHashDecoder()
								.withASymmetricPublicKeyForSignature(otherPublicKeyForSignature)
								.withRandomInputStream(new LimitedRandomInputStream(in, in.currentPosition()));

						try(RandomByteArrayOutputStream out=new RandomByteArrayOutputStream())
						{
							decoder.decodeAndCheckHashAndSignaturesIfNecessary(out);
							out.flush();
							otherPublicKeyForEncryption=out.getRandomInputStream().readObject(false);
							if (otherPublicKeyForEncryption.isPostQuantumKey() != myKeyPairForEncryption.isPostQuantumKey()) {
								otherPublicKeyForEncryption = null;
								throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN);
							}
							if (!otherPublicKeyForEncryption.useEncryptionAlgorithm())
							{
								otherPublicKeyForEncryption = null;
								throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN);
							}
						}
					} catch (ClassNotFoundException e) {
						throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN);
					}
					break;
				case 1:
					try(RandomByteArrayInputStream in=new RandomByteArrayInputStream(data))
					{
						try (KeyWrapperAlgorithm kw = new KeyWrapperAlgorithm(aSymmetricKeyWrapperType, myKeyPairForEncryption.getASymmetricPrivateKey(), otherPublicKeyForSignature)) {
							SymmetricSecretKey otherSecretKey = kw.unwrap(in.readWrappedEncryptedSymmetricSecretKey(false));
							generatedSecretKey = SymmetricSecretKey.getDerivedKey(mySecretKey, otherSecretKey);
						}
						if (mySecretKeyForSignature!=null)
						{
							try (KeyWrapperAlgorithm kw = new KeyWrapperAlgorithm(aSymmetricKeyWrapperType, myKeyPairForEncryption.getASymmetricPrivateKey(), otherPublicKeyForSignature)) {
								SymmetricSecretKey otherSecretKey = kw.unwrap(in.readWrappedEncryptedSymmetricSecretKey(false));
								generatedSecretKeyForSignature = SymmetricSecretKey.getDerivedKey(mySecretKeyForSignature, otherSecretKey);
							}
						}
					}
					break;

				default:
					throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN);
			}
		}
		catch (IOException e)
		{
			valid=false;
			throw e;
		}
	}

	@Override
	public boolean isPostQuantumAgreement() {
		return myKeyPairForEncryption.isPostQuantumKey();
	}


	protected SymmetricSecretKey getDerivedKey() {
		return generatedSecretKey;
	}

	public short getDerivedKeySizeBytes() {
		return (short)(keySizeBits/8);
	}
	protected SymmetricSecretKeyPair getDerivedSecretKeyPair()
	{
		return new SymmetricSecretKeyPair(generatedSecretKey, generatedSecretKeyForSignature);
	}
}

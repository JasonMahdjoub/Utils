package com.distrimind.util.crypto;
/*
Copyright or © or Corp. Jason Mahdjoub (01/04/2013)

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

import com.distrimind.util.io.Integrity;
import com.distrimind.util.io.MessageExternalizationException;
import com.distrimind.util.properties.MultiFormatProperties;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;


/**
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 5.12.0
 */
public abstract class EncryptionProfileCollectionWithEncryptedKeys extends EncryptionProfileProviderFactory implements EncryptionProfileProviderWithEncryptedKeys {



	protected EncryptionProfileCollectionWithEncryptedKeys() {
		super(null);
	}

	@SuppressWarnings("FieldMayBeFinal")
	public static class Profile extends MultiFormatProperties
	{
		private MessageDigestType messageDigestType;
		private IASymmetricPublicKey publicKeyForSignature;
		private WrappedEncryptedASymmetricPrivateKey encryptedPrivateKeyForSignature;
		private WrappedEncryptedSymmetricSecretKey encryptedSecretKeyForSignature;
		private WrappedEncryptedSymmetricSecretKey encryptedSecretKeyForEncryption;

		public MessageDigestType getMessageDigestType() {
			return messageDigestType;
		}

		public IASymmetricPublicKey getPublicKeyForSignature() {
			return publicKeyForSignature;
		}

		public WrappedEncryptedASymmetricPrivateKey getEncryptedPrivateKeyForSignature() {
			return encryptedPrivateKeyForSignature;
		}

		public WrappedEncryptedSymmetricSecretKey getEncryptedSecretKeyForSignature() {
			return encryptedSecretKeyForSignature;
		}

		public WrappedEncryptedSymmetricSecretKey getEncryptedSecretKeyForEncryption() {
			return encryptedSecretKeyForEncryption;
		}

		public Profile(MessageDigestType messageDigestType, IASymmetricPublicKey publicKeyForSignature, WrappedEncryptedASymmetricPrivateKey encryptedPrivateKeyForSignature, WrappedEncryptedSymmetricSecretKey encryptedSecretKeyForSignature, WrappedEncryptedSymmetricSecretKey encryptedSecretKeyForEncryption) {
			super(null);
			if (messageDigestType==null && publicKeyForSignature ==null && encryptedPrivateKeyForSignature==null && encryptedSecretKeyForSignature ==null && encryptedSecretKeyForEncryption ==null)
				throw new NullPointerException();
			this.messageDigestType = messageDigestType;
			this.publicKeyForSignature = publicKeyForSignature;
			this.encryptedPrivateKeyForSignature = encryptedPrivateKeyForSignature;
			this.encryptedSecretKeyForSignature = encryptedSecretKeyForSignature;
			this.encryptedSecretKeyForEncryption = encryptedSecretKeyForEncryption;
		}
	}


	private transient KeyWrapperAlgorithm keyWrapperAlgorithm=null;
	@SuppressWarnings("FieldMayBeFinal")
	private HashMap<Short, Profile> profiles=new HashMap<>();
	private short defaultKeyID=0;

	public boolean putProfile(short profileId,
							  MessageDigestType messageDigestType,
							  AbstractKeyPair<?, ?> keyPairForSignature,
							  SymmetricSecretKey secretKeyForSignature,
							  SymmetricSecretKey secretKeyForEncryption,
							  AbstractSecureRandom random,
							  boolean force,
							  boolean defaultProfile) throws IOException {
		KeyWrapperAlgorithm kwa=getKeyWrapperAlgorithm();
		return putProfile(profileId,
				messageDigestType,
				keyPairForSignature.getASymmetricPublicKey(),
				kwa.wrap(random, keyPairForSignature.getASymmetricPrivateKey()),
				kwa.wrap(random, secretKeyForSignature),
				kwa.wrap(random, secretKeyForEncryption),
				force, defaultProfile );
	}
	public boolean putProfile(short profileId,
							  MessageDigestType messageDigestType,
							  IASymmetricPublicKey publicKeyForSignature,
							  WrappedEncryptedASymmetricPrivateKey wrappedEncryptedASymmetricPrivateKeyForSignature,
							  WrappedEncryptedSymmetricSecretKey encryptedSecretKeyForSignature,
							  WrappedEncryptedSymmetricSecretKey encryptedSecretKeyForEncryption,
							  boolean force,
							  boolean defaultProfile)
	{
		if (force && profiles.containsKey(profileId))
			return false;
		profiles.put(profileId, new Profile(messageDigestType, publicKeyForSignature, wrappedEncryptedASymmetricPrivateKeyForSignature, encryptedSecretKeyForSignature, encryptedSecretKeyForEncryption));
		if (defaultProfile)
			defaultKeyID=profileId;
		return true;
	}

	private Profile getProfile(short keyID, boolean duringDecryptionPhase) throws IOException {
		Profile p=profiles.get(keyID);
		if (p==null)
		{
			if (duringDecryptionPhase)
				throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN);
			else
				throw new IOException();
		}
		return p;
	}

	@Override
	public MessageDigestType getMessageDigest(short keyID, boolean duringDecryptionPhase) throws IOException {

		return getProfile(keyID, duringDecryptionPhase).getMessageDigestType();
	}

	@Override
	public IASymmetricPublicKey getPublicKeyForSignature(short keyID) throws IOException {
		return getProfile(keyID, true).getPublicKeyForSignature();
	}

	@Override
	public Short getValidProfileIDFromPublicKeyForSignature(IASymmetricPublicKey publicKeyForSignature) {
		if (publicKeyForSignature==null)
			return null;
		return profiles.entrySet().stream().filter(p -> publicKeyForSignature.equals(p.getValue().publicKeyForSignature))
				.map(Map.Entry::getKey)
				.findAny()
				.orElse(null);
	}

	@Override
	public short getDefaultKeyID() {
		return defaultKeyID;
	}

	@Override
	public WrappedEncryptedSymmetricSecretKey getEncryptedSecretKeyForSignature(short keyID, boolean duringDecryptionPhase) throws IOException {
		return getProfile(keyID, duringDecryptionPhase).getEncryptedSecretKeyForSignature();
	}

	@Override
	public WrappedEncryptedSymmetricSecretKey getEncryptedSecretKeyForEncryption(short keyID, boolean duringDecryptionPhase) throws IOException {
		return getProfile(keyID, duringDecryptionPhase).getEncryptedSecretKeyForEncryption();
	}

	@Override
	public WrappedEncryptedASymmetricPrivateKey getEncryptedPrivateKeyForSignature(short keyID) throws IOException {
		return getProfile(keyID, false).getEncryptedPrivateKeyForSignature();
	}

	@Override
	public KeyWrapperAlgorithm getKeyWrapperAlgorithm() {
		if (keyWrapperAlgorithm==null)
			keyWrapperAlgorithm=getKeyWrapperAlgorithmInstance();
		return keyWrapperAlgorithm;
	}
	public abstract KeyWrapperAlgorithm getKeyWrapperAlgorithmInstance();

	@Override
	public void unloadKeyWrapperAlgorithm() {
		keyWrapperAlgorithm.clean();
		keyWrapperAlgorithm=null;
	}

	@Override
	protected EncryptionProfileProviderWithEncryptedKeys getEncryptionProfileProviderInstance() {
		return this;
	}
}

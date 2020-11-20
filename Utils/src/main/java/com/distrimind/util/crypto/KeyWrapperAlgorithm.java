package com.distrimind.util.crypto;

import com.distrimind.util.DecentralizedValue;
import com.distrimind.util.data_buffers.WrappedSecretData;
import com.distrimind.util.io.*;
import com.distrimind.util.properties.MultiFormatProperties;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

/**
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 5.10.0
 */
public class KeyWrapperAlgorithm extends MultiFormatProperties implements SecureExternalizable{
	private SymmetricKeyWrapperType symmetricKeyWrapperType;
	private ASymmetricKeyWrapperType aSymmetricKeyWrapperType;
	private AbstractKeyPair<?, ?> keyPair;
	private SymmetricSecretKey secretKey;

	private final static byte ENCRYPTION_WITH_SYMMETRIC_SECRET_KEY=2;
	private final static byte ENCRYPTION_WITH_ASYMMETRIC_KEY_PAIR=4;
	private byte mode;
	@SuppressWarnings("unused")
	private KeyWrapperAlgorithm()
	{
		super(null);
		symmetricKeyWrapperType=null;
		aSymmetricKeyWrapperType=null;
		secretKey=null;
		keyPair=null;
		mode=0;
	}

	public KeyWrapperAlgorithm(SymmetricKeyWrapperType symmetricKeyWrapperType, SymmetricSecretKey secretKey) {
		super(null);
		if (symmetricKeyWrapperType==null)
			throw new NullPointerException();
		if (secretKey==null)
			throw new NullPointerException();
		this.symmetricKeyWrapperType = symmetricKeyWrapperType;
		this.secretKey = secretKey;
		this.aSymmetricKeyWrapperType=null;
		this.keyPair=null;
		this.mode=ENCRYPTION_WITH_SYMMETRIC_SECRET_KEY;
	}

	public KeyWrapperAlgorithm(ASymmetricKeyWrapperType aSymmetricKeyWrapperType, AbstractKeyPair<?, ?> keyPair) {
		super(null);
		if (aSymmetricKeyWrapperType==null)
			throw new NullPointerException();
		if (keyPair==null)
			throw new NullPointerException();
		this.aSymmetricKeyWrapperType = aSymmetricKeyWrapperType;
		this.keyPair = keyPair;
		this.symmetricKeyWrapperType = null;
		this.secretKey = null;
		this.mode=ENCRYPTION_WITH_ASYMMETRIC_KEY_PAIR;
	}

	public KeyWrapperAlgorithm(SymmetricKeyWrapperType symmetricKeyWrapperType, PasswordHashType passwordHashType, WrappedPassword password) throws NoSuchAlgorithmException, NoSuchProviderException, IOException {
		this(symmetricKeyWrapperType, SymmetricKeyWrapperType.hashPasswordForSecretKeyEncryption(passwordHashType, password));
	}
	public WrappedEncryptedSymmetricSecretKeyString wrapString(AbstractSecureRandom random, SymmetricSecretKey secretKeyToWrap) throws IOException {
		return new WrappedEncryptedSymmetricSecretKeyString(wrap(random, secretKeyToWrap));
	}
	public WrappedEncryptedSymmetricSecretKey wrap(AbstractSecureRandom random, SymmetricSecretKey secretKeyToWrap) throws IOException {
		if (symmetricKeyWrapperType!=null)
		{
			return symmetricKeyWrapperType.wrapKey(secretKey, secretKeyToWrap, random);
		}
		else
		{
			return aSymmetricKeyWrapperType.wrapKey(random, keyPair.getASymmetricPublicKey(), secretKeyToWrap);
		}
	}
	public SymmetricSecretKey unwrap(WrappedEncryptedSymmetricSecretKeyString encryptedSecretKey) throws IOException {
		return unwrap(new WrappedEncryptedSymmetricSecretKey(encryptedSecretKey));
	}
	public SymmetricSecretKey unwrap(WrappedEncryptedSymmetricSecretKey encryptedSecretKey) throws IOException {
		if (symmetricKeyWrapperType!=null)
		{
			return symmetricKeyWrapperType.unwrapKey(secretKey, encryptedSecretKey);
		}
		else
		{
			return aSymmetricKeyWrapperType.unwrapKey(keyPair.getASymmetricPrivateKey(), encryptedSecretKey);
		}
	}
	public WrappedEncryptedASymmetricPrivateKeyString wrapString(AbstractSecureRandom random, IASymmetricPrivateKey privateKeyToWrap) throws IOException {
		return new WrappedEncryptedASymmetricPrivateKeyString(wrap(random, privateKeyToWrap));
	}
	public WrappedEncryptedASymmetricPrivateKey wrap(AbstractSecureRandom random, IASymmetricPrivateKey privateKeyToWrap) throws IOException {
		WrappedSecretData wsd=privateKeyToWrap.encode();
		try {
			AbstractEncryptionOutputAlgorithm cipher;
			if (symmetricKeyWrapperType != null) {
				cipher=new SymmetricEncryptionAlgorithm(random, secretKey);
			} else {
				cipher = new ClientASymmetricEncryptionAlgorithm(random, keyPair.getASymmetricPublicKey());
			}
			return new WrappedEncryptedASymmetricPrivateKey(cipher.encode(wsd.getBytes()));
		}
		finally {
			wsd.zeroize();
		}
	}
	public IASymmetricPrivateKey unwrap(WrappedEncryptedASymmetricPrivateKeyString privateKeyToUnwrap) throws IOException {
		return unwrap(new WrappedEncryptedASymmetricPrivateKey(privateKeyToUnwrap));
	}
	public IASymmetricPrivateKey unwrap(WrappedEncryptedASymmetricPrivateKey privateKeyToUnwrap) throws IOException {

		try {
			IEncryptionInputAlgorithm cipher;
			if (symmetricKeyWrapperType != null) {
				cipher=new SymmetricEncryptionAlgorithm(SecureRandomType.DEFAULT.getInstance(null), secretKey);
			} else {
				cipher = new ServerASymmetricEncryptionAlgorithm(keyPair.getASymmetricPrivateKey());
			}
			DecentralizedValue dv=DecentralizedValue.decode(cipher.decode(privateKeyToUnwrap.getBytes()), true);
			if (!(dv instanceof IASymmetricPrivateKey))
				throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN);
			return (IASymmetricPrivateKey)dv;
		} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
			throw new MessageExternalizationException(Integrity.FAIL);
		}
	}

	@Override
	public int getInternalSerializedSize() {
		switch (mode)
		{
			case ENCRYPTION_WITH_SYMMETRIC_SECRET_KEY:
				return SerializationTools.getInternalSize(SymmetricKeyWrapperType.DEFAULT)
						+SerializationTools.getInternalSize(secretKey);
			case ENCRYPTION_WITH_ASYMMETRIC_KEY_PAIR:
				return SerializationTools.getInternalSize(ASymmetricKeyWrapperType.DEFAULT)
						+SerializationTools.getInternalSize(keyPair);
			default:
				throw new IllegalAccessError();
		}
	}

	@Override
	public void writeExternal(SecuredObjectOutputStream out) throws IOException {

		switch (mode)
		{
			case ENCRYPTION_WITH_SYMMETRIC_SECRET_KEY:
				out.writeEnum(symmetricKeyWrapperType, false);
				out.writeObject(secretKey, false);
				break;
			case ENCRYPTION_WITH_ASYMMETRIC_KEY_PAIR:
				out.writeEnum(aSymmetricKeyWrapperType, false);
				out.writeObject(keyPair, false);
				break;
			default:
				throw new IOException();
		}
	}

	@Override
	public void readExternal(SecuredObjectInputStream in) throws IOException, ClassNotFoundException {
		mode=in.readByte();
		switch (mode)
		{
			case ENCRYPTION_WITH_SYMMETRIC_SECRET_KEY:
				symmetricKeyWrapperType=in.readEnum(false, SymmetricKeyWrapperType.class);
				secretKey=in.readObject(false, SymmetricSecretKey.class);
				aSymmetricKeyWrapperType=null;
				keyPair=null;
				break;
			case ENCRYPTION_WITH_ASYMMETRIC_KEY_PAIR:
				aSymmetricKeyWrapperType=in.readEnum(false, ASymmetricKeyWrapperType.class);
				keyPair=in.readObject(false, AbstractKeyPair.class);
				break;
			default:
				throw new MessageExternalizationException(Integrity.FAIL);
		}
	}
	public boolean isPostQuantumAlgorithm()
	{
		if (symmetricKeyWrapperType==null)
			return aSymmetricKeyWrapperType.isPostQuantumKeyAlgorithm();
		else
			return symmetricKeyWrapperType.isPostQuantumAlgorithm(secretKey.getKeySizeBits());
	}
}

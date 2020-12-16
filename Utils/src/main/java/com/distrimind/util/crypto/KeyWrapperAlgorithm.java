package com.distrimind.util.crypto;

import com.distrimind.util.Bits;
import com.distrimind.util.DecentralizedValue;
import com.distrimind.util.data_buffers.WrappedSecretData;
import com.distrimind.util.io.*;
import com.distrimind.util.properties.MultiFormatProperties;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Arrays;

/**
 * @author Jason Mahdjoub
 * @version 1.1
 * @since Utils 5.10.0
 */
public class KeyWrapperAlgorithm extends MultiFormatProperties implements SecureExternalizable, Zeroizable{
	public static final int MAX_SIZE_OF_WRAPPED_SYMMETRIC_SECRET_KEY_WITH_SYMMETRIC_ALGORITHM=SymmetricSecretKey.MAX_SIZE_IN_BYTES_OF_SYMMETRIC_KEY_FOR_SIGNATURE +16;
	public static final int MAX_SIZE_OF_WRAPPED_ASYMMETRIC_PRIVATE_KEY_WITH_SYMMETRIC_ALGORITHM=IASymmetricPrivateKey.MAX_SIZE_IN_BYTES_OF_PRIVATE_KEY+16;

	private SymmetricKeyWrapperType symmetricKeyWrapperType;
	private ASymmetricKeyWrapperType aSymmetricKeyWrapperType;
	private AbstractKeyPair<?, ?> keyPairForEncryption;
	private AbstractKeyPair<?, ?> keyPairForSignature;
	private SymmetricSecretKey secretKey;

	private final static byte ENCRYPTION_WITH_SYMMETRIC_SECRET_KEY=2;
	private final static byte ENCRYPTION_WITH_ASYMMETRIC_KEY_PAIR=4;
	private byte mode;

	@Override
	public void zeroize() {
		keyPairForEncryption.zeroize();
		keyPairForSignature.zeroize();
		secretKey.zeroize();
	}

	@SuppressWarnings("unused")
	private KeyWrapperAlgorithm()
	{
		super(null);
		symmetricKeyWrapperType=null;
		aSymmetricKeyWrapperType=null;
		secretKey=null;
		keyPairForEncryption =null;
		keyPairForSignature=null;
		mode=0;
	}

	public KeyWrapperAlgorithm(SymmetricKeyWrapperType symmetricKeyWrapperType, SymmetricSecretKey secretKey) {
		super(null);
		if (symmetricKeyWrapperType==null)
			throw new NullPointerException();
		if (secretKey==null)
			throw new NullPointerException();
		if (secretKey.getEncryptionAlgorithmType()!=symmetricKeyWrapperType.getSymmetricEncryptionType())
			throw new IllegalArgumentException();
		this.symmetricKeyWrapperType = symmetricKeyWrapperType;
		this.secretKey = secretKey;
		this.aSymmetricKeyWrapperType=null;
		this.keyPairForEncryption =null;
		this.mode=ENCRYPTION_WITH_SYMMETRIC_SECRET_KEY;
	}

	public KeyWrapperAlgorithm(ASymmetricKeyWrapperType aSymmetricKeyWrapperType, AbstractKeyPair<?, ?> keyPairForEncryption) {
		this(aSymmetricKeyWrapperType, keyPairForEncryption, null, false);
	}
	public KeyWrapperAlgorithm(ASymmetricKeyWrapperType aSymmetricKeyWrapperType, AbstractKeyPair<?, ?> keyPairForEncryption, AbstractKeyPair<?, ?> keyPairForSignature) {
		this(aSymmetricKeyWrapperType, keyPairForEncryption, keyPairForSignature, true);
	}
	private KeyWrapperAlgorithm(ASymmetricKeyWrapperType aSymmetricKeyWrapperType, AbstractKeyPair<?, ?> keyPairForEncryption, AbstractKeyPair<?, ?> keyPairForSignature, boolean includeSignature) {
		super(null);
		if (aSymmetricKeyWrapperType==null)
			throw new NullPointerException();
		if (keyPairForEncryption ==null)
			throw new NullPointerException();
		if (keyPairForSignature ==null && includeSignature)
			throw new NullPointerException();
		this.aSymmetricKeyWrapperType = aSymmetricKeyWrapperType;
		this.keyPairForEncryption = keyPairForEncryption;
		this.keyPairForSignature=keyPairForSignature;
		this.symmetricKeyWrapperType = null;
		this.secretKey = null;
		this.mode=ENCRYPTION_WITH_ASYMMETRIC_KEY_PAIR;
	}

	public KeyWrapperAlgorithm(SymmetricKeyWrapperType symmetricKeyWrapperType, PasswordHashType passwordHashType, WrappedPassword password) throws NoSuchAlgorithmException, NoSuchProviderException, IOException {
		this(symmetricKeyWrapperType, SymmetricKeyWrapperType.hashPasswordForSecretKeyEncryption(symmetricKeyWrapperType.getSymmetricEncryptionType(), passwordHashType, password));
	}
	public WrappedEncryptedSymmetricSecretKeyString wrapString(AbstractSecureRandom random, SymmetricSecretKey secretKeyToWrap) throws IOException {
		return new WrappedEncryptedSymmetricSecretKeyString(wrap(random, secretKeyToWrap));
	}
	private byte[] sign(byte[] encoded) throws IOException {
		if (aSymmetricKeyWrapperType!=null && keyPairForSignature!=null) {
			try {
				ASymmetricAuthenticatedSignerAlgorithm signer=new ASymmetricAuthenticatedSignerAlgorithm(keyPairForSignature.getASymmetricPrivateKey());
				byte[] signature=signer.sign(encoded);
				byte[] res=new byte[2+encoded.length+signature.length];
				Bits.putUnsignedInt16Bits(res, 0, signature.length);
				System.arraycopy(signature, 0, res, 2, signature.length);
				System.arraycopy(encoded, 0, res, 2+signature.length, encoded.length);
				Arrays.fill(encoded, (byte)0);
				return res;

			} catch (NoSuchProviderException | NoSuchAlgorithmException e) {
				throw new IOException(e);
			}
		}
		else
			return encoded;
	}
	private int checkSignature(byte[] encoded) throws IOException {
		if (aSymmetricKeyWrapperType!=null && keyPairForSignature!=null) {
			try {
				ASymmetricAuthenticatedSignatureCheckerAlgorithm checker=new ASymmetricAuthenticatedSignatureCheckerAlgorithm(keyPairForSignature.getASymmetricPublicKey());
				int size=Bits.getUnsignedInt16Bits(encoded, 0);
				int offM=size+2;
				if (offM<=encoded.length)
					throw new MessageExternalizationException(Integrity.FAIL);
				if (!checker.verify(encoded, offM, encoded.length-offM, encoded, 2, size))
					throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN);
				return offM;

			} catch (NoSuchProviderException | NoSuchAlgorithmException | MessageExternalizationException e) {
				throw new IOException(e);
			}
		}
		else
			return 0;
	}

	public WrappedEncryptedSymmetricSecretKey wrap(AbstractSecureRandom random, SymmetricSecretKey secretKeyToWrap) throws IOException {
		if (symmetricKeyWrapperType!=null)
		{
			if (symmetricKeyWrapperType.getAlgorithmName()==null) {
				SymmetricEncryptionAlgorithm cipher = new SymmetricEncryptionAlgorithm(random, secretKey);
				return new WrappedEncryptedSymmetricSecretKey(cipher.encode(secretKeyToWrap.encode().getBytes()));
			}
			else {
				return symmetricKeyWrapperType.wrapKey(secretKey, secretKeyToWrap, random);
			}
		}
		else
		{
			return aSymmetricKeyWrapperType.wrapKey(random, keyPairForEncryption.getASymmetricPublicKey(), secretKeyToWrap);
		}
	}
	public SymmetricSecretKey unwrap(WrappedEncryptedSymmetricSecretKeyString encryptedSecretKey) throws IOException {
		return unwrap(new WrappedEncryptedSymmetricSecretKey(encryptedSecretKey));
	}
	public SymmetricSecretKey unwrap(WrappedEncryptedSymmetricSecretKey encryptedSecretKey) throws IOException {
		if (symmetricKeyWrapperType!=null)
		{
			if (symmetricKeyWrapperType.getAlgorithmName()==null)
			{
				try {
					SymmetricEncryptionAlgorithm cipher = new SymmetricEncryptionAlgorithm(SecureRandomType.DEFAULT.getInstance(null), secretKey);
					AbstractKey ak=SymmetricSecretKey.decode(cipher.decode(encryptedSecretKey.getBytes()));
					if (ak instanceof SymmetricSecretKey)
						return (SymmetricSecretKey)ak;
					else
						throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN);
				} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
					throw new IOException(e);
				}
			}
			else
				return symmetricKeyWrapperType.unwrapKey(secretKey, encryptedSecretKey);
		}
		else
		{
			return aSymmetricKeyWrapperType.unwrapKey(keyPairForEncryption.getASymmetricPrivateKey(), encryptedSecretKey);
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
				cipher = new ClientASymmetricEncryptionAlgorithm(random, keyPairForEncryption.getASymmetricPublicKey());
			}
			return new WrappedEncryptedASymmetricPrivateKey(sign(cipher.encode(wsd.getBytes())));
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
				cipher = new ServerASymmetricEncryptionAlgorithm(keyPairForEncryption.getASymmetricPrivateKey());
			}
			int offM=checkSignature(privateKeyToUnwrap.getBytes());
			DecentralizedValue dv=DecentralizedValue.decode(cipher.decode(privateKeyToUnwrap.getBytes(), offM, privateKeyToUnwrap.getBytes().length-offM), true);
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
						+SerializationTools.getInternalSize(keyPairForEncryption)
						+SerializationTools.getInternalSize(keyPairForSignature);
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
				out.writeObject(keyPairForEncryption, false);
				out.writeObject(keyPairForSignature, true);
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
				keyPairForEncryption =null;
				keyPairForSignature=null;
				break;
			case ENCRYPTION_WITH_ASYMMETRIC_KEY_PAIR:
				aSymmetricKeyWrapperType=in.readEnum(false, ASymmetricKeyWrapperType.class);
				keyPairForEncryption =in.readObject(false, AbstractKeyPair.class);
				this.keyPairForSignature=in.readObject(false, AbstractKeyPair.class);
				secretKey=null;
				symmetricKeyWrapperType=null;
				break;
			default:
				throw new MessageExternalizationException(Integrity.FAIL);
		}
	}
	public boolean isPostQuantumAlgorithm()
	{
		if (symmetricKeyWrapperType==null)
			return aSymmetricKeyWrapperType.isPostQuantumKeyAlgorithm() && (keyPairForSignature==null || keyPairForSignature.isPostQuantumKey());
		else
			return symmetricKeyWrapperType.isPostQuantumAlgorithm(secretKey.getKeySizeBits());
	}
}

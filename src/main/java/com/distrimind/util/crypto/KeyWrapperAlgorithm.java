package com.distrimind.util.crypto;

import com.distrimind.util.AutoZeroizable;
import com.distrimind.util.Bits;
import com.distrimind.util.Cleanable;
import com.distrimind.util.DecentralizedValue;
import com.distrimind.util.data_buffers.WrappedData;
import com.distrimind.util.data_buffers.WrappedSecretData;
import com.distrimind.util.io.*;
import com.distrimind.util.properties.MultiFormatProperties;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Arrays;
import java.util.Objects;

/**
 * @author Jason Mahdjoub
 * @version 2.1
 * @since Utils 5.10.0
 */
public class KeyWrapperAlgorithm extends MultiFormatProperties implements SecureExternalizable, AutoZeroizable {

	private static final class Finalizer extends Cleaner
	{

		private IASymmetricPrivateKey privateKeyForEncryption, privateKeyForSignature;
		private IASymmetricPublicKey publicKeyForEncryption, publicKeyForSignature;
		private SymmetricSecretKey secretKeyForSignature;
		private SymmetricSecretKey secretKeyForEncryption;

		private Finalizer(Cleanable cleanable) {
			super(cleanable);
		}

		@Override
		protected void performCleanup() {
			publicKeyForEncryption=null;
			privateKeyForEncryption=null;
			publicKeyForSignature=null;
			privateKeyForSignature=null;
			secretKeyForEncryption =null;
			secretKeyForSignature=null;
		}
	}
	private SymmetricKeyWrapperType symmetricKeyWrapperType;
	private ASymmetricKeyWrapperType aSymmetricKeyWrapperType;
	private final Finalizer finalizer;

	private final static byte ENCRYPTION_WITH_SYMMETRIC_SECRET_KEY=2;
	private final static byte ENCRYPTION_WITH_ASYMMETRIC_KEY_PAIR=4;
	private final static byte SIGNATURE_WITH_ASYMMETRIC_KEY_PAIR=8;
	private final static byte SIGNATURE_WITH_SYMMETRIC_SECRET_KEY=16;
	private byte mode;


	@SuppressWarnings("unused")
	private KeyWrapperAlgorithm()
	{
		super(null);
		finalizer=new Finalizer(this);
		symmetricKeyWrapperType=null;
		aSymmetricKeyWrapperType=null;
		finalizer.secretKeyForEncryption =null;
		finalizer.privateKeyForEncryption=null;
		finalizer.privateKeyForSignature =null;
		finalizer.publicKeyForEncryption=null;
		finalizer.publicKeyForSignature=null;
		mode=0;
	}
	public KeyWrapperAlgorithm(SymmetricKeyWrapperType symmetricKeyWrapperType, SymmetricSecretKey secretKeyForEncryption) {
		this(symmetricKeyWrapperType, secretKeyForEncryption, false);
	}
	public KeyWrapperAlgorithm(SymmetricKeyWrapperType symmetricKeyWrapperType, SymmetricSecretKey secretKeyForEncryption, boolean signatureNotNecessary) {
		this(symmetricKeyWrapperType, secretKeyForEncryption, null, null, null, false, false, signatureNotNecessary);
	}
	public KeyWrapperAlgorithm(SymmetricKeyWrapperType symmetricKeyWrapperType, SymmetricSecretKey secretKeyForEncryption, SymmetricSecretKey secretKeyForSignature) {
		this(symmetricKeyWrapperType, secretKeyForEncryption, secretKeyForSignature, null, null, false, true, false);
	}
	public KeyWrapperAlgorithm(SymmetricKeyWrapperType symmetricKeyWrapperType, SymmetricSecretKey secretKeyForEncryption, IASymmetricPublicKey publicKeyForSignature) {
		this(symmetricKeyWrapperType, secretKeyForEncryption, null, publicKeyForSignature, null, true, false, false);
	}
	public KeyWrapperAlgorithm(SymmetricKeyWrapperType symmetricKeyWrapperType, SymmetricSecretKey secretKeyForEncryption, AbstractKeyPair<?, ?> keyPairForSignature) {
		this(symmetricKeyWrapperType, secretKeyForEncryption, null, keyPairForSignature.getASymmetricPublicKey(), keyPairForSignature.getASymmetricPrivateKey(), true, false, false);
	}
	public KeyWrapperAlgorithm(SymmetricKeyWrapperType symmetricKeyWrapperType, SymmetricSecretKey secretKeyForEncryption, SymmetricSecretKey secretKeyForSignature, IASymmetricPublicKey publicKeyForSignature) {
		this(symmetricKeyWrapperType, secretKeyForEncryption, secretKeyForSignature, publicKeyForSignature, null, true, true, false);
	}

	public KeyWrapperAlgorithm(SymmetricKeyWrapperType symmetricKeyWrapperType, SymmetricSecretKey secretKeyForEncryption, SymmetricSecretKey secretKeyForSignature, AbstractKeyPair<?, ?> keyPairForSignature) {
		this(symmetricKeyWrapperType, secretKeyForEncryption, secretKeyForSignature, keyPairForSignature.getASymmetricPublicKey(), keyPairForSignature.getASymmetricPrivateKey(), true, true, false);
	}
	private KeyWrapperAlgorithm(SymmetricKeyWrapperType symmetricKeyWrapperType, SymmetricSecretKey secretKeyForEncryption, SymmetricSecretKey secretKeyForSignature, IASymmetricPublicKey publicKeyForSignature, IASymmetricPrivateKey privateKeyForSignature, boolean includeASymmetricSignature, boolean includeSecretKeyForSignature, boolean signatureNotNecessary) {
		this();
		if (symmetricKeyWrapperType==null)
			throw new NullPointerException();
		if (secretKeyForEncryption ==null)
			throw new NullPointerException();
		if (secretKeyForEncryption.getEncryptionAlgorithmType()==null)
			throw new IllegalArgumentException();
		if (symmetricKeyWrapperType!=SymmetricKeyWrapperType.CLASSIC_ENCRYPTION && !Objects.equals(symmetricKeyWrapperType.getSymmetricEncryptionType().getAlgorithmName(), secretKeyForEncryption.getEncryptionAlgorithmType().getAlgorithmName()))
			throw new IllegalArgumentException("secretKeyForEncryption.getEncryptionAlgorithmType()="+secretKeyForEncryption.getEncryptionAlgorithmType()+", symmetricKeyWrapperType.getSymmetricEncryptionType()="+symmetricKeyWrapperType.getSymmetricEncryptionType());
		if (publicKeyForSignature ==null && privateKeyForSignature==null && includeASymmetricSignature)
			throw new NullPointerException();
		if (includeSecretKeyForSignature && secretKeyForSignature==null)
			throw new NullPointerException();
		this.symmetricKeyWrapperType = symmetricKeyWrapperType;
		if (signatureNotNecessary)
		{
			SymmetricEncryptionType t=null;
			if (secretKeyForEncryption.getEncryptionAlgorithmType()==SymmetricEncryptionType.BC_CHACHA20_POLY1305)
				t=SymmetricEncryptionType.BC_CHACHA20_NO_RANDOM_ACCESS;
			else if (secretKeyForEncryption.getEncryptionAlgorithmType()==SymmetricEncryptionType.CHACHA20_POLY1305)
				t=SymmetricEncryptionType.CHACHA20_NO_RANDOM_ACCESS;
			if (t!=null)
				secretKeyForEncryption=new SymmetricSecretKey(t, secretKeyForEncryption);
		}

		this.finalizer.secretKeyForEncryption = secretKeyForEncryption;
		this.finalizer.secretKeyForSignature=secretKeyForSignature;
		this.mode=ENCRYPTION_WITH_SYMMETRIC_SECRET_KEY;
		this.finalizer.privateKeyForSignature = privateKeyForSignature;
		this.finalizer.publicKeyForSignature = publicKeyForSignature;
		if (includeASymmetricSignature)
			this.mode+=SIGNATURE_WITH_ASYMMETRIC_KEY_PAIR;
		if (includeSecretKeyForSignature)
			this.mode+=SIGNATURE_WITH_SYMMETRIC_SECRET_KEY;
		if (symmetricKeyWrapperType.getAlgorithmName()==null && (secretKeyForEncryption.getEncryptionAlgorithmType()==null ||
				(!signatureNotNecessary && !secretKeyForEncryption.getEncryptionAlgorithmType().isAuthenticatedAlgorithm()
						&& !useSignature())))
			throw new IllegalArgumentException("This key wrapping type and this secret key for encryption must be used with a signature algorithm");
	}
	public KeyWrapperAlgorithm(ASymmetricKeyWrapperType aSymmetricKeyWrapperType, IASymmetricPublicKey publicKeyForEncryption) {
		this(aSymmetricKeyWrapperType, publicKeyForEncryption, null, null, null, null, false, false);
	}
	public KeyWrapperAlgorithm(ASymmetricKeyWrapperType aSymmetricKeyWrapperType, IASymmetricPublicKey publicKeyForEncryption, SymmetricSecretKey secretKeyForSignature) {
		this(aSymmetricKeyWrapperType, publicKeyForEncryption, null, null, null, secretKeyForSignature, false, true);
	}
	public KeyWrapperAlgorithm(ASymmetricKeyWrapperType aSymmetricKeyWrapperType, IASymmetricPrivateKey privateKeyForDecryption) {
		this(aSymmetricKeyWrapperType, null, privateKeyForDecryption, null, null, null, false, false);
	}
	public KeyWrapperAlgorithm(ASymmetricKeyWrapperType aSymmetricKeyWrapperType, IASymmetricPrivateKey privateKeyForDecryption, SymmetricSecretKey secretKeyForSignature) {
		this(aSymmetricKeyWrapperType, null, privateKeyForDecryption, null, null, secretKeyForSignature, false, true);
	}
	public KeyWrapperAlgorithm(ASymmetricKeyWrapperType aSymmetricKeyWrapperType, AbstractKeyPair<?, ?> keyPairForEncryption) {
		this(aSymmetricKeyWrapperType, keyPairForEncryption, null, null, false, false);
	}
	public KeyWrapperAlgorithm(ASymmetricKeyWrapperType aSymmetricKeyWrapperType, AbstractKeyPair<?, ?> keyPairForEncryption, SymmetricSecretKey secretKeyForSignature) {
		this(aSymmetricKeyWrapperType, keyPairForEncryption, null, secretKeyForSignature, false, true);
	}
	public KeyWrapperAlgorithm(ASymmetricKeyWrapperType aSymmetricKeyWrapperType, IASymmetricPublicKey publicKeyForEncryption, IASymmetricPrivateKey privateKeyForSignature) {
		this(aSymmetricKeyWrapperType, publicKeyForEncryption, null, null, privateKeyForSignature,null, true, false);
	}
	public KeyWrapperAlgorithm(ASymmetricKeyWrapperType aSymmetricKeyWrapperType, IASymmetricPublicKey publicKeyForEncryption, IASymmetricPrivateKey privateKeyForSignature, SymmetricSecretKey secretKeyForSignature) {
		this(aSymmetricKeyWrapperType, publicKeyForEncryption, null, null, privateKeyForSignature,secretKeyForSignature, true, true);
	}
	public KeyWrapperAlgorithm(ASymmetricKeyWrapperType aSymmetricKeyWrapperType, IASymmetricPrivateKey privateKeyForEncryption, IASymmetricPublicKey publicKeyForSignature) {
		this(aSymmetricKeyWrapperType, null, privateKeyForEncryption, publicKeyForSignature, null, null, true, false);
	}
	public KeyWrapperAlgorithm(ASymmetricKeyWrapperType aSymmetricKeyWrapperType, IASymmetricPrivateKey privateKeyForEncryption, IASymmetricPublicKey publicKeyForSignature, SymmetricSecretKey secretKeyForSignature) {
		this(aSymmetricKeyWrapperType, null, privateKeyForEncryption, publicKeyForSignature, null, secretKeyForSignature, true, true);
	}
	public KeyWrapperAlgorithm(ASymmetricKeyWrapperType aSymmetricKeyWrapperType, AbstractKeyPair<?, ?> keyPairForEncryption, AbstractKeyPair<?, ?> keyPairForSignature) {
		this(aSymmetricKeyWrapperType, keyPairForEncryption, keyPairForSignature, null, true, false);
	}
	public KeyWrapperAlgorithm(ASymmetricKeyWrapperType aSymmetricKeyWrapperType, AbstractKeyPair<?, ?> keyPairForEncryption, AbstractKeyPair<?, ?> keyPairForSignature, SymmetricSecretKey secretKeyForSignature) {
		this(aSymmetricKeyWrapperType, keyPairForEncryption, keyPairForSignature, secretKeyForSignature, true, true);
	}
	private KeyWrapperAlgorithm(ASymmetricKeyWrapperType aSymmetricKeyWrapperType, AbstractKeyPair<?, ?> keyPairForEncryption, AbstractKeyPair<?, ?> keyPairForSignature, SymmetricSecretKey secretKeyForSignature, boolean includeASymmetricSignature, boolean includeSecretKeyForSignature) {
		this(aSymmetricKeyWrapperType, keyPairForEncryption.getASymmetricPublicKey(), keyPairForEncryption.getASymmetricPrivateKey(), keyPairForSignature==null?null:keyPairForSignature.getASymmetricPublicKey(), keyPairForSignature==null?null:keyPairForSignature.getASymmetricPrivateKey(), secretKeyForSignature, includeASymmetricSignature, includeSecretKeyForSignature);
	}

	private KeyWrapperAlgorithm(ASymmetricKeyWrapperType aSymmetricKeyWrapperType, IASymmetricPublicKey publicKeyForEncryption, IASymmetricPrivateKey privateKeyForEncryption, IASymmetricPublicKey publicKeyForSignature, IASymmetricPrivateKey privateKeyForSignature, SymmetricSecretKey secretKeyForSignature, boolean includeASymmetricSignature, boolean includeSecretKeyForSignature) {
		super(null);
		if (aSymmetricKeyWrapperType==null)
			throw new NullPointerException();
		if (privateKeyForEncryption ==null && publicKeyForEncryption==null)
			throw new NullPointerException();
		if (publicKeyForSignature ==null && privateKeyForSignature==null && includeASymmetricSignature)
			throw new NullPointerException();
		if (includeASymmetricSignature && ((privateKeyForEncryption==null)!=(publicKeyForSignature==null) || (publicKeyForEncryption==null)!=(privateKeyForSignature==null)))
			throw new NullPointerException();
		if (includeSecretKeyForSignature && secretKeyForSignature==null)
			throw new NullPointerException();

		assert includeSecretKeyForSignature || secretKeyForSignature==null;
		assert includeASymmetricSignature || (privateKeyForSignature==null && publicKeyForSignature==null);
		finalizer=new Finalizer(this);
		this.aSymmetricKeyWrapperType = aSymmetricKeyWrapperType;
		this.finalizer.privateKeyForEncryption=privateKeyForEncryption;
		this.finalizer.publicKeyForEncryption=publicKeyForEncryption;
		this.finalizer.privateKeyForSignature = privateKeyForSignature;
		this.finalizer.publicKeyForSignature = publicKeyForSignature;
		this.symmetricKeyWrapperType = null;
		this.finalizer.secretKeyForEncryption = null;
		this.finalizer.secretKeyForSignature=secretKeyForSignature;
		this.mode=ENCRYPTION_WITH_ASYMMETRIC_KEY_PAIR;
		if (includeASymmetricSignature)
			this.mode+=SIGNATURE_WITH_ASYMMETRIC_KEY_PAIR;
		if (includeSecretKeyForSignature)
			this.mode+=SIGNATURE_WITH_SYMMETRIC_SECRET_KEY;
		if (!aSymmetricKeyWrapperType.wrappingIncludeSignature()
				&& !useSignature())
			throw new IllegalArgumentException("This key wrapping type and this public key for encryption must be used with a signature algorithm");
	}

	public KeyWrapperAlgorithm(SymmetricKeyWrapperType symmetricKeyWrapperType, PasswordHashType passwordHashType, WrappedPassword password) throws NoSuchAlgorithmException, NoSuchProviderException, IOException {
		this(symmetricKeyWrapperType, SymmetricKeyWrapperType.hashPasswordForSecretKeyEncryption(symmetricKeyWrapperType.getSymmetricEncryptionType(), passwordHashType, password));
	}
	public WrappedEncryptedSymmetricSecretKeyString wrapString(AbstractSecureRandom random, SymmetricSecretKey secretKeyToWrap) throws IOException {
		return new WrappedEncryptedSymmetricSecretKeyString(wrap(random, secretKeyToWrap));
	}
	private WrappedEncryptedSymmetricSecretKey signSymmetricSecretKey(byte[] encoded) throws IOException {
		return new WrappedEncryptedSymmetricSecretKey(sign(encoded));
	}
	private WrappedEncryptedSymmetricSecretKey signSymmetricSecretKey(WrappedData encoded) throws IOException {
		byte[] res=sign(encoded.getBytes());
		if (res==encoded.getBytes() && encoded instanceof WrappedSecretData)
			return new WrappedEncryptedSymmetricSecretKey(res.clone());
		else
			return new WrappedEncryptedSymmetricSecretKey(res);
	}
	private WrappedEncryptedASymmetricPrivateKey signASymmetricPrivateKey(byte[] encoded) throws IOException {
		return new WrappedEncryptedASymmetricPrivateKey(sign(encoded));
	}

	private byte[] sign(byte[] encoded) throws IOException {
		if (((this.mode & SIGNATURE_WITH_ASYMMETRIC_KEY_PAIR)==SIGNATURE_WITH_ASYMMETRIC_KEY_PAIR) && finalizer.privateKeyForSignature==null)
			throw new IOException("Private key for signature has not be given");
		if (((this.mode & SIGNATURE_WITH_SYMMETRIC_SECRET_KEY)==SIGNATURE_WITH_SYMMETRIC_SECRET_KEY) && finalizer.secretKeyForSignature==null)
			throw new IOException("Secret key for signature has not be given");
		try {
			SymmetricAuthenticatedSignerAlgorithm symSigner = null;
			if (finalizer.secretKeyForSignature != null) {
				symSigner = new SymmetricAuthenticatedSignerAlgorithm(finalizer.secretKeyForSignature);
				symSigner.init();
			}
			int symSignSize = symSigner == null ? 0 : symSigner.getMacLengthBytes();
			if (finalizer.privateKeyForSignature != null) {

				ASymmetricAuthenticatedSignerAlgorithm signer = new ASymmetricAuthenticatedSignerAlgorithm(finalizer.privateKeyForSignature);
				signer.init();
				byte[] signature = signer.sign(encoded);
				byte[] res = new byte[2 + encoded.length + signature.length+symSignSize];
				Bits.putUnsignedInt16Bits(res, symSignSize, signature.length);
				System.arraycopy(signature, 0, res, symSignSize+2, signature.length);
				System.arraycopy(encoded, 0, res, symSignSize+2 + signature.length, encoded.length);
				Arrays.fill(encoded, (byte) 0);
				encoded=res;
			}
			if (symSigner!=null)
			{
				int s;
				if (finalizer.privateKeyForSignature==null) {
					s=encoded.length;
					byte[] res=new byte[s+symSignSize];
					System.arraycopy(encoded, 0, res, symSignSize, s);
					Arrays.fill(encoded, (byte)0);
					encoded=res;
				}
				else
					s = encoded.length - symSignSize;
				symSigner.sign(encoded, symSignSize, s, encoded, 0, symSignSize);
			}
			return encoded;
		} catch (NoSuchProviderException | NoSuchAlgorithmException e) {
			throw new IOException(e);
		}
	}
	private int checkSignature(byte[] encoded) throws IOException {
		if (((this.mode & SIGNATURE_WITH_ASYMMETRIC_KEY_PAIR)==SIGNATURE_WITH_ASYMMETRIC_KEY_PAIR) && finalizer.publicKeyForSignature==null)
			throw new IOException("Public key used to check signature is lacking");
		if (((this.mode & SIGNATURE_WITH_SYMMETRIC_SECRET_KEY)==SIGNATURE_WITH_SYMMETRIC_SECRET_KEY) && finalizer.secretKeyForSignature==null)
			throw new IOException("Secret key for signature has not be given");
		try {
			SymmetricAuthenticatedSignatureCheckerAlgorithm symChecker = null;
			if (finalizer.secretKeyForSignature != null) {
				symChecker = new SymmetricAuthenticatedSignatureCheckerAlgorithm(finalizer.secretKeyForSignature);
			}
			int symSignSize = symChecker == null ? 0 : symChecker.getMacLengthBytes();
			int offM=0;
			if (symChecker!=null)
			{
				if (!symChecker.verify(encoded, symSignSize, encoded.length-symSignSize, encoded, 0, symSignSize))
					throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN);
				offM+=symSignSize;
			}
			if (finalizer.publicKeyForSignature != null) {

				ASymmetricAuthenticatedSignatureCheckerAlgorithm checker = new ASymmetricAuthenticatedSignatureCheckerAlgorithm(finalizer.publicKeyForSignature);
				int size = Bits.getUnsignedInt16Bits(encoded, offM);
				int aSigOff=offM+2;
				offM += size + 2;
				if (offM >= encoded.length)
					throw new MessageExternalizationException(Integrity.FAIL);
				if (!checker.verify(encoded, offM, encoded.length - offM, encoded, aSigOff, size))
					throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN);
			}
			return offM;
		} catch (NoSuchProviderException | NoSuchAlgorithmException | MessageExternalizationException e) {
			throw new IOException(e);
		}
	}
	@SuppressWarnings("BooleanMethodIsAlwaysInverted")
	private boolean useSignature()
	{
		return ((this.mode & SIGNATURE_WITH_SYMMETRIC_SECRET_KEY)==SIGNATURE_WITH_SYMMETRIC_SECRET_KEY)
				|| ((this.mode & SIGNATURE_WITH_ASYMMETRIC_KEY_PAIR)==SIGNATURE_WITH_ASYMMETRIC_KEY_PAIR);
	}

	public WrappedEncryptedSymmetricSecretKey wrap(AbstractSecureRandom random, SymmetricSecretKey secretKeyToWrap) throws IOException {
		if (((this.mode & ENCRYPTION_WITH_ASYMMETRIC_KEY_PAIR)==ENCRYPTION_WITH_ASYMMETRIC_KEY_PAIR) && finalizer.publicKeyForEncryption==null)
			throw new IOException("Public key used for encryption is not available");


		if (symmetricKeyWrapperType!=null)
		{
			if (symmetricKeyWrapperType.getAlgorithmName()==null) {
				SymmetricEncryptionAlgorithm cipher = new SymmetricEncryptionAlgorithm(random, finalizer.secretKeyForEncryption, false);
				WrappedSecretData wsd=secretKeyToWrap.encode();
				WrappedEncryptedSymmetricSecretKey res= signSymmetricSecretKey(cipher.encode(wsd.getBytes()));
				wsd.getBytes();

				return res;
			}
			else {
				WrappedEncryptedSymmetricSecretKey w=symmetricKeyWrapperType.wrapKey(finalizer.secretKeyForEncryption, secretKeyToWrap, random);
				return signSymmetricSecretKey(w);
			}
		}
		else
		{
			WrappedEncryptedSymmetricSecretKey w=aSymmetricKeyWrapperType.wrapKey(random, finalizer.publicKeyForEncryption, secretKeyToWrap);
			return signSymmetricSecretKey(w);
		}
	}
	public SymmetricSecretKey unwrap(WrappedEncryptedSymmetricSecretKeyString encryptedSecretKey) throws IOException {
		return unwrap(new WrappedEncryptedSymmetricSecretKey(encryptedSecretKey));
	}
	public SymmetricSecretKey unwrap(WrappedEncryptedSymmetricSecretKey encryptedSecretKey) throws IOException {
		if (((this.mode & ENCRYPTION_WITH_ASYMMETRIC_KEY_PAIR)==ENCRYPTION_WITH_ASYMMETRIC_KEY_PAIR) && finalizer.privateKeyForEncryption==null)
			throw new IOException("Private key used for encryption is not available");
		if (finalizer.publicKeyForEncryption!=null && finalizer.privateKeyForEncryption==null)
			throw new IOException("Private key used for decryption is lacking");
		if (symmetricKeyWrapperType!=null)
		{
			if (symmetricKeyWrapperType.getAlgorithmName()==null)
			{
				try {
					SymmetricEncryptionAlgorithm cipher = new SymmetricEncryptionAlgorithm(SecureRandomType.DEFAULT.getInstance(null), finalizer.secretKeyForEncryption, false);
					int off=checkSignature(encryptedSecretKey.getBytes());
					AbstractKey ak=SymmetricSecretKey.decode(cipher.decode(encryptedSecretKey.getBytes(), off, encryptedSecretKey.getBytes().length-off), true);
					encryptedSecretKey.getBytes();//gc delayed
					if (ak instanceof SymmetricSecretKey)
						return (SymmetricSecretKey)ak;
					else
						throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN);
				} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
					throw new IOException(e);
				}
			}
			else {
				int off=checkSignature(encryptedSecretKey.getBytes());
				if (off>0) {
					try(WrappedEncryptedSymmetricSecretKey e2 = new WrappedEncryptedSymmetricSecretKey(Arrays.copyOfRange(encryptedSecretKey.getBytes(), off, encryptedSecretKey.getBytes().length))) {
						encryptedSecretKey.getBytes();//gc delayed
						SymmetricSecretKey symmetricSecretKey = symmetricKeyWrapperType.unwrapKey(finalizer.secretKeyForEncryption, e2);
						e2.getBytes();//gc delayed
						return symmetricSecretKey;
					}
				}
				else {
					SymmetricSecretKey symmetricSecretKey = symmetricKeyWrapperType.unwrapKey(finalizer.secretKeyForEncryption, encryptedSecretKey);
					encryptedSecretKey.getBytes();//gc delayed
					return symmetricSecretKey;
				}
			}
		}
		else
		{
			int off=checkSignature(encryptedSecretKey.getBytes());
			if (off>0) {
				try(WrappedEncryptedSymmetricSecretKey e2 = new WrappedEncryptedSymmetricSecretKey(Arrays.copyOfRange(encryptedSecretKey.getBytes(), off, encryptedSecretKey.getBytes().length)))
				{
					SymmetricSecretKey res= aSymmetricKeyWrapperType.unwrapKey(finalizer.privateKeyForEncryption, e2);
					e2.getBytes();//gc delayed
					return res;
				}
			}
			else {
				SymmetricSecretKey res= aSymmetricKeyWrapperType.unwrapKey(finalizer.privateKeyForEncryption, encryptedSecretKey);
				encryptedSecretKey.getBytes();//gc delayed
				return res;
			}
		}
	}
	public WrappedEncryptedASymmetricPrivateKeyString wrapString(AbstractSecureRandom random, IASymmetricPrivateKey privateKeyToWrap) throws IOException {
		return new WrappedEncryptedASymmetricPrivateKeyString(wrap(random, privateKeyToWrap));
	}
	public WrappedEncryptedASymmetricPrivateKey wrap(AbstractSecureRandom random, IASymmetricPrivateKey privateKeyToWrap) throws IOException {
		if (mode==ENCRYPTION_WITH_ASYMMETRIC_KEY_PAIR && finalizer.publicKeyForEncryption==null)
			throw new IOException("Public key used for encryption is not available");
		try (WrappedSecretData wsd=privateKeyToWrap.encode()){
			try(AbstractEncryptionOutputAlgorithm cipher=(symmetricKeyWrapperType != null)?new SymmetricEncryptionAlgorithm(random, finalizer.secretKeyForEncryption, false):new ClientASymmetricEncryptionAlgorithm(random, finalizer.publicKeyForEncryption)) {
				WrappedEncryptedASymmetricPrivateKey res= signASymmetricPrivateKey(cipher.encode(wsd.getBytes()));
				cipher.getBlockModeCounterBytes();
				return res;
			}
		}
	}
	public IASymmetricPrivateKey unwrap(WrappedEncryptedASymmetricPrivateKeyString privateKeyToUnwrap) throws IOException {
		return unwrap(new WrappedEncryptedASymmetricPrivateKey(privateKeyToUnwrap));
	}
	public IASymmetricPrivateKey unwrap(WrappedEncryptedASymmetricPrivateKey privateKeyToUnwrap) throws IOException {
		if (mode==ENCRYPTION_WITH_ASYMMETRIC_KEY_PAIR && finalizer.privateKeyForEncryption==null)
			throw new IOException("Private key used for encryption is not available");
		if (finalizer.publicKeyForEncryption!=null && finalizer.privateKeyForEncryption==null)
			throw new IOException("Private key used for decryption is lacking");
		try {
			IEncryptionInputAlgorithm cipher;
			if (symmetricKeyWrapperType != null) {
				cipher=new SymmetricEncryptionAlgorithm(SecureRandomType.DEFAULT.getInstance(null), finalizer.secretKeyForEncryption, false);
			} else {
				cipher = new ServerASymmetricEncryptionAlgorithm(finalizer.privateKeyForEncryption);
			}
			int offM=checkSignature(privateKeyToUnwrap.getBytes());
			DecentralizedValue dv = DecentralizedValue.decode(cipher.decode(privateKeyToUnwrap.getBytes(), offM, privateKeyToUnwrap.getBytes().length - offM), true);
			privateKeyToUnwrap.getBytes();//gc delayed
			if (!(dv instanceof IASymmetricPrivateKey))
				throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN);
			return (IASymmetricPrivateKey) dv;

		} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
			throw new MessageExternalizationException(Integrity.FAIL);
		}

	}

	@Override
	public int getInternalSerializedSize() {
		if ((mode & ENCRYPTION_WITH_SYMMETRIC_SECRET_KEY)==ENCRYPTION_WITH_SYMMETRIC_SECRET_KEY)
		{
			return SerializationTools.getInternalSize(SymmetricKeyWrapperType.DEFAULT)
					+SerializationTools.getInternalSize(finalizer.secretKeyForEncryption)
					+SerializationTools.getInternalSize(finalizer.secretKeyForSignature);
		}
		else if ((mode & ENCRYPTION_WITH_ASYMMETRIC_KEY_PAIR)==ENCRYPTION_WITH_ASYMMETRIC_KEY_PAIR)
		{
			return SerializationTools.getInternalSize(ASymmetricKeyWrapperType.DEFAULT)
					+SerializationTools.getInternalSize(finalizer.publicKeyForEncryption)
					+SerializationTools.getInternalSize(finalizer.privateKeyForEncryption)
					+SerializationTools.getInternalSize(finalizer.publicKeyForSignature)
					+SerializationTools.getInternalSize(finalizer.privateKeyForSignature)
					+SerializationTools.getInternalSize(finalizer.secretKeyForSignature);
		}
		throw new IllegalAccessError();
	}

	@Override
	public void writeExternal(SecuredObjectOutputStream out) throws IOException {
		out.writeByte(mode);
		if ((mode & SIGNATURE_WITH_SYMMETRIC_SECRET_KEY)==SIGNATURE_WITH_SYMMETRIC_SECRET_KEY) {
			out.writeObject(finalizer.secretKeyForSignature, false);
		}
		if ((mode & SIGNATURE_WITH_ASYMMETRIC_KEY_PAIR)==SIGNATURE_WITH_ASYMMETRIC_KEY_PAIR) {
			out.writeObject(finalizer.privateKeyForSignature, true);
			out.writeObject(finalizer.publicKeyForSignature, finalizer.privateKeyForSignature!=null);
		}

		if ((mode & ENCRYPTION_WITH_SYMMETRIC_SECRET_KEY)==ENCRYPTION_WITH_SYMMETRIC_SECRET_KEY) {
			out.writeEnum(symmetricKeyWrapperType, false);
			out.writeObject(finalizer.secretKeyForEncryption, false);

		}
		else if ((mode & ENCRYPTION_WITH_ASYMMETRIC_KEY_PAIR)==ENCRYPTION_WITH_ASYMMETRIC_KEY_PAIR)
		{
			out.writeEnum(aSymmetricKeyWrapperType, false);
			out.writeObject(finalizer.publicKeyForEncryption, false);
			out.writeObject(finalizer.privateKeyForEncryption, false);
		}
		else throw new IOException();
	}

	@Override
	public void readExternal(SecuredObjectInputStream in) throws IOException, ClassNotFoundException {
		finalizer.performCleanup();
		mode=in.readByte();
		if ((mode & SIGNATURE_WITH_SYMMETRIC_SECRET_KEY)==SIGNATURE_WITH_SYMMETRIC_SECRET_KEY) {
			finalizer.secretKeyForSignature=in.readObject(false);
		}
		else
			finalizer.secretKeyForSignature=null;
		if ((mode & SIGNATURE_WITH_SYMMETRIC_SECRET_KEY)==SIGNATURE_WITH_SYMMETRIC_SECRET_KEY) {
			finalizer.privateKeyForSignature = in.readObject(true);
			finalizer.publicKeyForSignature = in.readObject(finalizer.privateKeyForSignature!=null);

		}
		else
		{
			finalizer.publicKeyForSignature = null;
			finalizer.privateKeyForSignature = null;
		}

		if ((mode & ENCRYPTION_WITH_SYMMETRIC_SECRET_KEY)==ENCRYPTION_WITH_SYMMETRIC_SECRET_KEY) {
			symmetricKeyWrapperType = in.readEnum(false, SymmetricKeyWrapperType.class);
			finalizer.secretKeyForEncryption = in.readObject(false);
			aSymmetricKeyWrapperType = null;
			finalizer.publicKeyForEncryption = null;
			finalizer.privateKeyForEncryption = null;
		}
		else if ((mode & ENCRYPTION_WITH_ASYMMETRIC_KEY_PAIR)==ENCRYPTION_WITH_ASYMMETRIC_KEY_PAIR) {
			aSymmetricKeyWrapperType = in.readEnum(false, ASymmetricKeyWrapperType.class);
			finalizer.publicKeyForEncryption = in.readObject(false);
			finalizer.privateKeyForEncryption = in.readObject(false);
			if ((finalizer.privateKeyForSignature != null || finalizer.publicKeyForSignature != null) && ((finalizer.privateKeyForEncryption == null) != (finalizer.publicKeyForSignature == null) || (finalizer.publicKeyForEncryption == null) != (finalizer.privateKeyForSignature == null)))
				throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN);
			finalizer.secretKeyForEncryption = null;
			symmetricKeyWrapperType = null;
		}
		else
			throw new MessageExternalizationException(Integrity.FAIL);

	}
	public boolean isPostQuantumAlgorithm()
	{
		if (symmetricKeyWrapperType==null)
			return aSymmetricKeyWrapperType.isPostQuantumKeyAlgorithm()
					&& (finalizer.publicKeyForSignature==null || finalizer.publicKeyForSignature.isPostQuantumKey())
					&& (finalizer.privateKeyForSignature==null || finalizer.privateKeyForSignature.isPostQuantumKey())
					&& (finalizer.publicKeyForEncryption==null || finalizer.publicKeyForEncryption.isPostQuantumKey())
					&& (finalizer.privateKeyForEncryption==null || finalizer.privateKeyForEncryption.isPostQuantumKey())
					&& (finalizer.secretKeyForSignature==null || finalizer.secretKeyForSignature.isPostQuantumKey())
					;
		else {
			return symmetricKeyWrapperType.isPostQuantumAlgorithm(finalizer.secretKeyForEncryption.getKeySizeBits()) && (finalizer.secretKeyForSignature==null || finalizer.secretKeyForSignature.isPostQuantumKey());
		}
	}
	public int getWrappedSymmetricSecretKeySizeInBytes(SymmetricSecretKey keyToWrap) throws IOException {
		return getWrappedSymmetricSecretKeySizeInBytes(keyToWrap.getEncryptionAlgorithmType(), keyToWrap.getKeySizeBytes());
	}
	public int getWrappedSymmetricSecretKeySizeInBytes(SymmetricEncryptionType keyType, int keySizeBytes) throws IOException {
		int encryptedSize;
		try {
			keySizeBytes=keyType.getEncodedSymmetricSecretKeySizeBytes(keySizeBytes);
			if (symmetricKeyWrapperType.getAlgorithmName() == null) {

				SymmetricEncryptionAlgorithm cipher = new SymmetricEncryptionAlgorithm(SecureRandomType.DEFAULT.getSingleton(null), finalizer.secretKeyForEncryption, false);
				encryptedSize = (int) cipher.getOutputSizeAfterEncryption(SymmetricSecretKey.getEncodedKeySizeInBytes(keySizeBytes));


			} else {

				encryptedSize = 11+keySizeBytes;
			}


			if (finalizer.secretKeyForSignature != null) {
				encryptedSize += finalizer.secretKeyForSignature.getAuthenticatedSignatureAlgorithmType().getSignatureSizeInBits() / 8;
			}

			if (finalizer.privateKeyForSignature != null) {
				ASymmetricAuthenticatedSignerAlgorithm signer = new ASymmetricAuthenticatedSignerAlgorithm(finalizer.privateKeyForSignature);
				signer.init();
				encryptedSize += signer.getMacLengthBytes() + 2;
			}
			return encryptedSize;
		} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
			throw new IOException(e);
		}


	}

	public static void main(String []arg) throws NoSuchAlgorithmException, NoSuchProviderException, IOException {
		for (SymmetricKeyWrapperType kwt : SymmetricKeyWrapperType.values()) {
			SymmetricEncryptionType set;
			switch (kwt)
			{
				case BC_FIPS_AES:case BC_FIPS_AES_WITH_PADDING:case DEFAULT:
				set=SymmetricEncryptionType.AES_GCM;
				break;
				case CLASSIC_ENCRYPTION:
					set=SymmetricEncryptionType.BC_CHACHA20_POLY1305;
					break;
				default:
					throw new IllegalAccessError();
			}
			SymmetricSecretKey mainKey = set.getKeyGenerator(SecureRandomType.DEFAULT.getSingleton(null)).generateKey();
			for (SymmetricEncryptionType et : SymmetricEncryptionType.values()) {
				if (et.getCodeProviderForEncryption()==CodeProvider.GNU_CRYPTO)
					continue;
				if (et.getAlgorithmName().toLowerCase().contains("aes")
						|| et.getAlgorithmName().toLowerCase().contains("chacha20")
						|| et.getAlgorithmName().toLowerCase().contains("twofish")
						|| et.getAlgorithmName().toLowerCase().contains("serpent")
						|| et.getAlgorithmName().toLowerCase().contains("anubis")) {
					for (short keySizeBits : new short[]{128, 256}) {
						if (et.getAlgorithmName().toLowerCase().contains("chacha20") && keySizeBits<256)
							continue;
						SymmetricSecretKey k = et.getKeyGenerator(SecureRandomType.DEFAULT.getSingleton(null), keySizeBits).generateKey();
						KeyWrapperAlgorithm alg=new KeyWrapperAlgorithm(kwt, mainKey);

						System.out.println(kwt + " , " + et + ", " + k.getKeySizeBits() + ", " + alg.wrap(SecureRandomType.DEFAULT.getSingleton(null), k).getBytes().length+", "+alg.getWrappedSymmetricSecretKeySizeInBytes(mainKey.getEncryptionAlgorithmType(), keySizeBits/8));
					}
				}
			}
		}
	}


}

package com.distrimind.util.crypto;
/*
Copyright or © or Copr. Jason Mahdjoub (01/04/2013)

jason.mahdjoub@distri-mind.fr

This software (Object Oriented Database (OOD)) is a computer program 
whose purpose is to manage a local database with the object paradigm 
and the java langage 

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

import com.distrimind.util.io.RandomByteArrayOutputStream;
import com.distrimind.util.io.SecureExternalizableWithoutInnerSizeControl;
import com.distrimind.util.io.SecuredObjectInputStream;
import com.distrimind.util.io.SecuredObjectOutputStream;
import org.bouncycastle.crypto.*;
import org.bouncycastle.crypto.digests.*;
import org.bouncycastle.pqc.crypto.MessageEncryptor;
import org.bouncycastle.pqc.crypto.mceliece.*;
import org.bouncycastle.pqc.math.linearalgebra.GF2Matrix;
import org.bouncycastle.pqc.math.linearalgebra.GF2mField;
import org.bouncycastle.pqc.math.linearalgebra.Permutation;
import org.bouncycastle.pqc.math.linearalgebra.PolynomialGF2mSmallM;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

/**
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 4.5.0
 */
public class BCMcElieceCipher extends AbstractCipher{

	private MessageEncryptor mcElieceCipher;
	private final ASymmetricEncryptionType encryptionType;
	private final boolean cca2;

	private ByteArrayOutputStream out=null;
	private boolean encrypt;

	public BCMcElieceCipher(ASymmetricEncryptionType encryptionType) {
		if (encryptionType==null)
			throw new NullPointerException();
		this.encryptionType = encryptionType;
		if (!this.encryptionType.name().startsWith("BCPQC_MCELIECE_"))
			throw new IllegalArgumentException();
		cca2=this.encryptionType.name().contains("CCA2");
	}

	private MessageEncryptor getMcElieceCipher()
	{
		if (encryptionType.name().contains("Fujisaki"))
			return new McElieceFujisakiCipher();
		else if (encryptionType.name().contains("Pointcheval"))
			return new McEliecePointchevalCipher();
		else if (encryptionType.name().contains("KobaraImai"))
			return new McElieceKobaraImaiCipher();
		else
			return new McElieceCipher();
	}

	private static final int MAX_GF2MATRIX_SIZE=256*1024;

	static class PrivateKey implements AsymmetricPrivateKey, SecureExternalizableWithoutInnerSizeControl {
		private McEliecePrivateKeyParameters privateKeyParameters;
		private volatile byte []encoded=null;
		private volatile Integer hashCode=null;
		PrivateKey()
		{
			privateKeyParameters=null;
		}

		public McEliecePrivateKeyParameters getPrivateKeyParameters() {
			return privateKeyParameters;
		}

		PrivateKey(McEliecePrivateKeyParameters privateKeyParameters) {
			if (privateKeyParameters==null)
				throw new NullPointerException();
			this.privateKeyParameters = privateKeyParameters;
		}

		@Override
		public byte[] getEncoded() {
			if (encoded==null) {
				RandomByteArrayOutputStream out = new RandomByteArrayOutputStream();
				try {
					writeExternal(out);
					encoded = out.getBytes();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
			return encoded;
		}

		@Override
		public Algorithm getAlgorithm() {
			return null;
		}

		@Override
		public boolean equals(Object o) {
			if (o==null)
				return false;
			if (o==this)
				return true;
			if (o.getClass()==this.getClass()) {
				return Arrays.equals(getEncoded(), ((PrivateKey) o).getEncoded());
			}
			return false;
		}

		@Override
		public int hashCode() {
			if (hashCode==null)
				hashCode=Arrays.hashCode(getEncoded());
			return hashCode;
		}

		@Override
		public void writeExternal(SecuredObjectOutputStream out) throws IOException {

			out.writeBytesArray(privateKeyParameters.getField().getEncoded(), false, Short.MAX_VALUE);
			out.writeBytesArray(privateKeyParameters.getGoppaPoly().getEncoded(), false, Short.MAX_VALUE);
			out.writeBytesArray(privateKeyParameters.getH().getEncoded(), false, MAX_GF2MATRIX_SIZE);
			out.writeBytesArray(privateKeyParameters.getP1().getEncoded(), false, Short.MAX_VALUE);
			out.writeBytesArray(privateKeyParameters.getP2().getEncoded(), false, Short.MAX_VALUE);
			out.writeBytesArray(privateKeyParameters.getSInv().getEncoded(), false, MAX_GF2MATRIX_SIZE);
			PolynomialGF2mSmallM[] qinv=privateKeyParameters.getQInv();
			if (qinv.length>Short.MAX_VALUE)
				throw new IOException();
			out.writeShort(qinv.length);
			for (PolynomialGF2mSmallM polynomialGF2mSmallM : qinv)
				out.writeBytesArray(polynomialGF2mSmallM.getEncoded(), false, Short.MAX_VALUE);
			out.writeInt(privateKeyParameters.getK());
			out.writeInt(privateKeyParameters.getN());
		}

		@Override
		public void readExternal(SecuredObjectInputStream in) throws IOException {
			try {
				byte[] field=in.readBytesArray(false, Short.MAX_VALUE);
				byte[] goppaPoly=in.readBytesArray(false, Short.MAX_VALUE);
				byte[] h=in.readBytesArray(false, MAX_GF2MATRIX_SIZE);
				byte[] p1=in.readBytesArray(false, Short.MAX_VALUE);
				byte[] p2=in.readBytesArray(false, Short.MAX_VALUE);
				byte[] sinv=in.readBytesArray(false, MAX_GF2MATRIX_SIZE);
				int s=in.readShort();
				if (s<=0)
					throw new IOException();
				byte[][] qinv=new byte[s][];
				for (int i=0;i<s;i++)
					qinv[i]=in.readBytesArray(false, Short.MAX_VALUE);
				int k=in.readInt();
				int n=in.readInt();
				privateKeyParameters=new McEliecePrivateKeyParameters(n, k, field, goppaPoly, sinv, p1, p2, h, qinv);
			}
			catch(Exception e)
			{
				throw new IOException(e);
			}
		}

		public void zeroize()
		{
			if (privateKeyParameters!=null)
			{
				for (int[] a : privateKeyParameters.getH().getIntArray())
					Arrays.fill(a, 0);
			}
		}

	}

	static class PrivateKeyCCA2 implements AsymmetricPrivateKey, SecureExternalizableWithoutInnerSizeControl {
		private McElieceCCA2PrivateKeyParameters privateKeyParameters;
		private volatile byte []encoded=null;
		private volatile Integer hashCode=null;

		public McElieceCCA2PrivateKeyParameters getPrivateKeyParameters() {
			return privateKeyParameters;
		}

		PrivateKeyCCA2()
		{
			privateKeyParameters=null;
		}

		PrivateKeyCCA2(McElieceCCA2PrivateKeyParameters privateKeyParameters) {
			if (privateKeyParameters==null)
				throw new NullPointerException();
			this.privateKeyParameters = privateKeyParameters;
		}

		@Override
		public byte[] getEncoded() {
			if (encoded==null) {
				RandomByteArrayOutputStream out = new RandomByteArrayOutputStream();
				try {
					writeExternal(out, false);
					encoded = out.getBytes();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
			return encoded;
		}

		@Override
		public Algorithm getAlgorithm() {
			return null;
		}

		@Override
		public boolean equals(Object o) {
			if (o==null)
				return false;
			if (o==this)
				return true;
			if (o.getClass()==this.getClass()) {
				return Arrays.equals(getEncoded(), ((PrivateKey) o).getEncoded());
			}
			return false;
		}

		@Override
		public int hashCode() {
			if (hashCode==null)
				hashCode=Arrays.hashCode(getEncoded());
			return hashCode;
		}
		@Override
		public void writeExternal(SecuredObjectOutputStream out) throws IOException {
				writeExternal(out, true);
		}

		public void zeroize()
		{
			if (privateKeyParameters!=null)
			{
				for (int[] a : privateKeyParameters.getH().getIntArray())
					Arrays.fill(a, 0);
			}
		}


		public void writeExternal(SecuredObjectOutputStream out, boolean writeDigest) throws IOException {

			out.writeBytesArray(privateKeyParameters.getField().getEncoded(), false, Short.MAX_VALUE);
			out.writeBytesArray(privateKeyParameters.getGoppaPoly().getEncoded(), false, Short.MAX_VALUE);
			out.writeBytesArray(privateKeyParameters.getH().getEncoded(), false, MAX_GF2MATRIX_SIZE);
			out.writeBytesArray(privateKeyParameters.getP().getEncoded(), false, Short.MAX_VALUE);
			if (writeDigest)
				out.writeString(privateKeyParameters.getDigest(), false, 512);
			out.writeInt(privateKeyParameters.getK());
			out.writeInt(privateKeyParameters.getN());
		}
		@Override
		public void readExternal(SecuredObjectInputStream in) throws IOException {
			readExternal(in, (String)null);
		}
		public void readExternal(SecuredObjectInputStream in, ASymmetricEncryptionType type) throws IOException {
			String digest;
			if (type.name().contains("SHA256"))
				digest="SHA-256";
			else if (type.name().contains("SHA384"))
				digest="SHA-384";
			else if (type.name().contains("SHA512"))
				digest="SHA-512";
			else
				throw new IOException();
			readExternal(in, digest);
		}

		public void readExternal(SecuredObjectInputStream in, String digest) throws IOException {
			try {
				GF2mField field=new GF2mField(in.readBytesArray(false, Short.MAX_VALUE));
				PolynomialGF2mSmallM goppaPoly=new PolynomialGF2mSmallM(field, in.readBytesArray(false, Short.MAX_VALUE));
				GF2Matrix h=new GF2Matrix(in.readBytesArray(false, MAX_GF2MATRIX_SIZE));
				Permutation p=new Permutation(in.readBytesArray(false, Short.MAX_VALUE));
				if (digest==null)
					digest=in.readString(false, 512);

				int k=in.readInt();
				int n=in.readInt();

				privateKeyParameters=new McElieceCCA2PrivateKeyParameters(n, k, field, goppaPoly, h, p, digest);

			}
			catch(Exception e)
			{
				throw new IOException(e);
			}
		}
	}

	static class PublicKey implements AsymmetricPublicKey, SecureExternalizableWithoutInnerSizeControl {
		private McEliecePublicKeyParameters publicKeyParameters;
		private volatile byte []encoded=null;
		private volatile Integer hashCode=null;

		public McEliecePublicKeyParameters getPublicKeyParameters() {
			return publicKeyParameters;
		}

		public PublicKey() {
			publicKeyParameters=null;
		}

		public PublicKey(McEliecePublicKeyParameters publicKeyParameters) {
			if (publicKeyParameters==null)
				throw new NullPointerException();
			this.publicKeyParameters = publicKeyParameters;
		}

		@Override
		public byte[] getEncoded() {
			if (encoded==null) {
				RandomByteArrayOutputStream out = new RandomByteArrayOutputStream();
				try {
					writeExternal(out);
					encoded = out.getBytes();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
			return encoded;
		}

		@Override
		public Algorithm getAlgorithm() {
			return null;
		}

		@Override
		public boolean equals(Object o) {
			if (o==null)
				return false;
			if (o==this)
				return true;
			if (o.getClass()==this.getClass()) {
				return Arrays.equals(getEncoded(), ((PrivateKey) o).getEncoded());
			}
			return false;
		}

		@Override
		public int hashCode() {
			if (hashCode==null)
				hashCode=Arrays.hashCode(getEncoded());
			return hashCode;
		}
		public void zeroize()
		{
			if (publicKeyParameters!=null)
			{
				for (int[] a : publicKeyParameters.getG().getIntArray())
					Arrays.fill(a, 0);
			}
		}

		@Override
		public void writeExternal(SecuredObjectOutputStream out) throws IOException {

			out.writeBytesArray(publicKeyParameters.getG().getEncoded(), false, MAX_GF2MATRIX_SIZE);
			out.writeInt(publicKeyParameters.getN());
			out.writeInt(publicKeyParameters.getT());
		}

		@Override
		public void readExternal(SecuredObjectInputStream in) throws IOException {
			try {
				byte[] g=in.readBytesArray(false, MAX_GF2MATRIX_SIZE);
				int n=in.readInt();
				int t=in.readInt();
				publicKeyParameters=new McEliecePublicKeyParameters(n, t, new GF2Matrix(g));
			}
			catch(Exception e)
			{
				throw new IOException(e);
			}
		}
	}

	static class PublicKeyCCA2 implements AsymmetricPublicKey, SecureExternalizableWithoutInnerSizeControl {
		private McElieceCCA2PublicKeyParameters publicKeyParameters;
		private volatile byte []encoded=null;
		private volatile Integer hashCode=null;

		public McElieceCCA2PublicKeyParameters getPublicKeyParameters() {
			return publicKeyParameters;
		}

		public PublicKeyCCA2() {
			publicKeyParameters=null;
		}
		public void zeroize()
		{
			if (publicKeyParameters!=null)
			{
				for (int[] a : publicKeyParameters.getG().getIntArray())
					Arrays.fill(a, 0);
			}
		}


		public PublicKeyCCA2(McElieceCCA2PublicKeyParameters publicKeyParameters) {
			if (publicKeyParameters==null)
				throw new NullPointerException();
			this.publicKeyParameters = publicKeyParameters;
		}

		@Override
		public byte[] getEncoded() {
			if (encoded==null) {
				RandomByteArrayOutputStream out = new RandomByteArrayOutputStream();
				try {
					writeExternal(out, false);
					encoded = out.getBytes();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
			return encoded;
		}

		@Override
		public Algorithm getAlgorithm() {
			return null;
		}

		@Override
		public boolean equals(Object o) {
			if (o==null)
				return false;
			if (o==this)
				return true;
			if (o.getClass()==this.getClass()) {
				return Arrays.equals(getEncoded(), ((PrivateKey) o).getEncoded());
			}
			return false;
		}

		@Override
		public int hashCode() {
			if (hashCode==null)
				hashCode=Arrays.hashCode(getEncoded());
			return hashCode;
		}

		@Override
		public void writeExternal(SecuredObjectOutputStream out) throws IOException {

			writeExternal(out, true);
		}

		public void writeExternal(SecuredObjectOutputStream out, boolean includeType) throws IOException {

			out.writeBytesArray(publicKeyParameters.getG().getEncoded(), false, MAX_GF2MATRIX_SIZE);
			if (includeType)
				out.writeString(publicKeyParameters.getDigest(), false, 512);
			out.writeInt(publicKeyParameters.getN());
			out.writeInt(publicKeyParameters.getT());
		}

		@Override
		public void readExternal(SecuredObjectInputStream in) throws IOException {
			readExternal(in, (String)null);
		}
		public void readExternal(SecuredObjectInputStream in, ASymmetricEncryptionType type) throws IOException {
			String digest;
			if (type.name().contains("SHA256"))
				digest="SHA-256";
			else if (type.name().contains("SHA384"))
				digest="SHA-384";
			else if (type.name().contains("SHA512"))
				digest="SHA-512";
			else
				throw new IOException();
			readExternal(in, digest);
		}
		public void readExternal(SecuredObjectInputStream in, String digest) throws IOException {
			try {
				GF2Matrix g=new GF2Matrix(in.readBytesArray(false, MAX_GF2MATRIX_SIZE));
				if (digest==null)
					digest=in.readString(false, 512);
				int n=in.readInt();
				int t=in.readInt();
				publicKeyParameters=new McElieceCCA2PublicKeyParameters(n, t, g, digest);
			}
			catch(Exception e)
			{
				throw new IOException(e);
			}
		}
	}

	static class KeyPairGenerator extends AbstractKeyPairGenerator
	{
		private McElieceKeyPairGenerator mcElieceKeyPairGenerator=null;

		private final String digest;
		private int keySize;
		private long keyExpiration;

		KeyPairGenerator(ASymmetricEncryptionType encryptionType) {
			super(encryptionType);
			if (!this.encryptionType.name().startsWith("BCPQC_MCELIECE_"))
				throw new IllegalArgumentException();
			boolean cca2=this.encryptionType.name().contains("CCA2");
			if (cca2)
				throw new IllegalAccessError();
			if (this.encryptionType.name().contains("SHA256"))
				digest="SHA-256";
			else if (this.encryptionType.name().contains("SHA384"))
				digest="SHA-384";
			else if (this.encryptionType.name().contains("SHA512"))
				digest="SHA-512";
			else
				throw new IllegalArgumentException();
		}
		Digest getDigest()
		{
			if (digest.equals("SHA-1"))
			{
				return new SHA1Digest();
			}
			if (digest.equals("SHA-224"))
			{
				return new SHA224Digest();
			}
			if (digest.equals("SHA-256"))
			{
				return new SHA256Digest();
			}
			if (digest.equals("SHA-384"))
			{
				return new SHA384Digest();
			}
			if (digest.equals("SHA-512"))
			{
				return new SHA512Digest();
			}

			throw new IllegalArgumentException("unrecognised digest algorithm: " + digest);
		}
		@Override
		public ASymmetricKeyPair generateKeyPair() {
			AsymmetricCipherKeyPair res= mcElieceKeyPairGenerator.generateKeyPair();
			return new ASymmetricKeyPair(new ASymmetricPrivateKey(encryptionType, new PrivateKey((McEliecePrivateKeyParameters) res.getPrivate()), keySize),
					new ASymmetricPublicKey(encryptionType, new PublicKey((McEliecePublicKeyParameters) res.getPublic()), keySize, keyExpiration));
		}

		@Override
		public String getAlgorithm() {
			return encryptionType.getAlgorithmName();
		}

		@Override
		public void initialize(int keysize, long expirationTime) throws NoSuchProviderException, NoSuchAlgorithmException {
			initialize(keysize, expirationTime, SecureRandomType.BC_FIPS_APPROVED_FOR_KEYS.getSingleton(null));
		}

		@Override
		public void initialize(int keysize, long expirationTime, AbstractSecureRandom random) {
			this.keySize=keysize;
			this.keyExpiration=expirationTime;
			mcElieceKeyPairGenerator=new McElieceKeyPairGenerator();
			mcElieceKeyPairGenerator.init(new McElieceKeyGenerationParameters(random, new McElieceParameters(keysize, getDigest())));
		}
	}

	static class KeyPairGeneratorCCA2 extends AbstractKeyPairGenerator
	{
		private McElieceCCA2KeyPairGenerator mcElieceKeyPairGenerator=null;

		private final String digest;
		private int keySize;
		private long keyExpiration;

		KeyPairGeneratorCCA2(ASymmetricEncryptionType encryptionType) {
			super(encryptionType);
			if (!this.encryptionType.name().startsWith("BCPQC_MCELIECE_"))
				throw new IllegalArgumentException();
			boolean cca2=this.encryptionType.name().contains("CCA2");
			if (!cca2)
				throw new IllegalAccessError();
			if (this.encryptionType.name().contains("SHA256"))
				digest="SHA-256";
			else if (this.encryptionType.name().contains("SHA384"))
				digest="SHA-384";
			else if (this.encryptionType.name().contains("SHA512"))
				digest="SHA-512";
			else
				throw new IllegalArgumentException();
		}

		@Override
		public ASymmetricKeyPair generateKeyPair() {
			AsymmetricCipherKeyPair res= mcElieceKeyPairGenerator.generateKeyPair();
			return new ASymmetricKeyPair(new ASymmetricPrivateKey(encryptionType, new PrivateKeyCCA2((McElieceCCA2PrivateKeyParameters) res.getPrivate()), keySize),
					new ASymmetricPublicKey(encryptionType, new PublicKeyCCA2((McElieceCCA2PublicKeyParameters) res.getPublic()), keySize, keyExpiration));
		}

		@Override
		public String getAlgorithm() {
			return encryptionType.getAlgorithmName();
		}

		@Override
		public void initialize(int keysize, long expirationTime) throws NoSuchProviderException, NoSuchAlgorithmException {
			initialize(keysize, expirationTime, SecureRandomType.BC_FIPS_APPROVED_FOR_KEYS.getSingleton(null));
		}

		@Override
		public void initialize(int keysize, long expirationTime, AbstractSecureRandom random) {
			this.keySize=keysize;
			this.keyExpiration=expirationTime;
			mcElieceKeyPairGenerator=new McElieceCCA2KeyPairGenerator();
			mcElieceKeyPairGenerator.init(new McElieceCCA2KeyGenerationParameters(random, new McElieceCCA2Parameters(keysize, digest)));
		}
	}

	@Override
	public byte[] doFinal() throws IllegalStateException, IllegalBlockSizeException, BadPaddingException {
		if (encrypt)
			return mcElieceCipher.messageEncrypt(out.toByteArray());
		else {
			try {
				return mcElieceCipher.messageDecrypt(out.toByteArray());
			} catch (BCInvalidCipherTextException e) {
				throw new IllegalStateException(e);
			}
		}
	}

	@Override
	public int doFinal(byte[] output, int outputOffset) throws IllegalStateException, IllegalBlockSizeException, BadPaddingException, ShortBufferException {
		byte[] res=doFinal();
		System.arraycopy(res, 0, output, outputOffset, res.length);
		return res.length;
	}

	@Override
	public byte[] doFinal(byte[] input, int inputOffset, int inputLength) throws IllegalStateException, IllegalBlockSizeException, BadPaddingException {
		update(input, inputOffset, inputLength);
		return doFinal();
	}

	@Override
	public int doFinal(byte[] input, int inputOffset, int inputLength, byte[] output, int outputOffset) throws IllegalStateException, IllegalBlockSizeException, BadPaddingException, ShortBufferException {
		update(input, inputOffset, inputLength, output, outputOffset);
		return doFinal(output, outputOffset);
	}

	@Override
	public String getAlgorithm() {
		return encryptionType.getAlgorithmName();
	}

	@Override
	public int getBlockSize() {
		if (mcElieceCipher.getClass()==McElieceCipher.class)
			return ((McElieceCipher)mcElieceCipher).maxPlainTextSize;
		else
			return Short.MAX_VALUE;
	}

	@Override
	public InputStream getCipherInputStream(final InputStream in) {

		return new InputStream() {
			private byte[] data=null;
			private int index=0;
			private void checkDataLoaded() throws IOException {
				if (data==null) {
					ByteArrayOutputStream out = new ByteArrayOutputStream();
					byte[] buf = new byte[2048];
					for (; ; ) {
						int nb=in.read(buf, 0, buf.length);
						if (nb<0)
							break;
						out.write(buf, 0, nb);
					}
					try {
						data=doFinal(out.toByteArray());
					} catch (IllegalBlockSizeException | BadPaddingException e) {
						throw new IOException(e);
					}

				}
			}

			@Override
			public int read() throws IOException {
				checkDataLoaded();
				if (data.length==index)
					return -1;
				return data[index++];
			}

			@Override
			public int read(byte[] b, int off, int len) {
				if (data.length==index)
					return -1;
				int l=Math.min(len, data.length-index);
				System.arraycopy(data, index, b, off, l);
				index+=l;
				return l;
			}
		};
	}

	@Override
	public OutputStream getCipherOutputStream(final OutputStream out) {
		return new OutputStream() {
			private ByteArrayOutputStream buf=new ByteArrayOutputStream();
			@Override
			public void write(int b) {
				buf.write(b);
			}

			@Override
			public void write(byte[] b, int off, int len)  {
				buf.write(b, off, len);
			}

			@Override
			public void close() throws IOException {
				try {
					byte[] res=doFinal(buf.toByteArray());
					out.write(res);
				} catch (IllegalBlockSizeException | BadPaddingException e) {
					throw new IOException(e);
				}
			}
		};
	}

	@Override
	public byte[] getIV() {
		return null;
	}

	@Override
	public int getOutputSize(int inputLength) throws IllegalStateException {

		return 0;
	}

	@Override
	public void init(int opmode, AbstractKey key, AbstractSecureRandom random) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException {
		out=new ByteArrayOutputStream();
		encrypt=opmode== Cipher.ENCRYPT_MODE || opmode==Cipher.WRAP_MODE;
		mcElieceCipher=getMcElieceCipher();
		if (cca2)
		{
			if (key instanceof ASymmetricPrivateKey)
			{
				mcElieceCipher.init(encrypt, ((PrivateKeyCCA2)key.toBouncyCastleKey()).privateKeyParameters);
			}
			else {
				mcElieceCipher.init(encrypt, ((PublicKeyCCA2)key.toBouncyCastleKey()).publicKeyParameters);
			}
		}
		else {

			if (key instanceof ASymmetricPrivateKey)
			{
				mcElieceCipher.init(encrypt, ((PrivateKey)key.toBouncyCastleKey()).privateKeyParameters);
			}
			else {
				mcElieceCipher.init(encrypt, ((PublicKey)key.toBouncyCastleKey()).publicKeyParameters);
			}
		}

	}

	@Override
	public void init(int opmode, AbstractKey key, byte[] iv) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidAlgorithmParameterException {
		try {
			init(opmode, key, SecureRandomType.BC_FIPS_APPROVED_FOR_KEYS.getSingleton(null));
		} catch (NoSuchProviderException e) {
			throw new InvalidAlgorithmParameterException(e);
		}
	}

	@Override
	public byte[] update(byte[] input, int inputOffset, int inputLength) throws IllegalStateException {
		out.write(input, inputOffset, inputLength);
		return empty;
	}
	private byte[] empty=new byte[0];

	@Override
	public int update(byte[] input, int inputOffset, int inputLength, byte[] output, int outputOffset) throws IllegalStateException, ShortBufferException {
		out.write(input, inputOffset, inputLength);
		return 0;
	}

	@Override
	public void updateAAD(byte[] ad, int offset, int size) {

	}
}

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

import com.distrimind.bouncycastle.pqc.legacy.crypto.mceliece.*;
import com.distrimind.util.AutoZeroizable;
import com.distrimind.util.Cleanable;
import com.distrimind.util.Zeroizable;
import com.distrimind.util.io.*;
import com.distrimind.bouncycastle.crypto.AsymmetricCipherKeyPair;
import com.distrimind.bouncycastle.crypto.Digest;
import com.distrimind.bouncycastle.crypto.InvalidCipherTextException;
import com.distrimind.bouncycastle.crypto.digests.*;
import com.distrimind.bouncycastle.crypto.params.ParametersWithRandom;
import com.distrimind.bcfips.crypto.Algorithm;
import com.distrimind.bcfips.crypto.AsymmetricPrivateKey;
import com.distrimind.bcfips.crypto.AsymmetricPublicKey;
import com.distrimind.bouncycastle.pqc.crypto.MessageEncryptor;
import com.distrimind.bouncycastle.pqc.legacy.math.linearalgebra.GF2Matrix;
import com.distrimind.bouncycastle.pqc.legacy.math.linearalgebra.GF2mField;
import com.distrimind.bouncycastle.pqc.legacy.math.linearalgebra.Permutation;
import com.distrimind.bouncycastle.pqc.legacy.math.linearalgebra.PolynomialGF2mSmallM;

import javax.crypto.Cipher;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

/**
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 4.5.0
 */
@SuppressWarnings("NullableProblems")
public class BCMcElieceCipher extends AbstractCipher{

	private MessageEncryptor mcElieceCipher;
	private final ASymmetricEncryptionType encryptionType;
	private final boolean cca2;

	private final ByteArrayOutputStream out=new ByteArrayOutputStream();
	private boolean encrypt;
	private int mode=-1;
	@Override
	public int getMode() {
		return mode;
	}


	public BCMcElieceCipher(ASymmetricEncryptionType encryptionType) {
		super();
		if (encryptionType==null)
			throw new NullPointerException();
		this.encryptionType = encryptionType.getDerivedType();
		if (!this.encryptionType.name().startsWith("BCPQC_MCELIECE_"))
			throw new IllegalArgumentException();
		cca2=this.encryptionType.name().contains("CCA2");
	}



	private MessageEncryptor getMcElieceCipher()
	{
		if (encryptionType.name().contains("FUJISAKI"))
			return new McElieceFujisakiCipher();
		else if (encryptionType.name().contains("POINTCHEVAL"))
			return new McEliecePointchevalCipher();
		else if (encryptionType.name().contains("KOBARA_IMAI"))
			return new McElieceKobaraImaiCipher();
		else
			return new McElieceCipher();
	}

	private static final int MAX_GF2MATRIX_SIZE=30*1024*1024;
	private final static class PrivateKeyFinalizer extends Cleanable.Cleaner
	{
		private McEliecePrivateKeyParameters privateKeyParameters;

		private PrivateKeyFinalizer(Cleanable cleanable) {
			super(cleanable);
		}

		@Override
		protected void performCleanup() {
			if (privateKeyParameters!=null)
			{
				for (int[] a : privateKeyParameters.getH().getIntArray())
					Arrays.fill(a, 0);
			}
		}
	}
	static class PrivateKey implements AsymmetricPrivateKey, SecureExternalizableWithoutInnerSizeControl, AutoZeroizable {

		private volatile byte []encoded=null;
		private volatile Integer hashCode=null;
		private final PrivateKeyFinalizer finalizer;

		PrivateKey()
		{
			finalizer=new PrivateKeyFinalizer(this);
			finalizer.privateKeyParameters=null;
		}

		public McEliecePrivateKeyParameters getPrivateKeyParameters() {
			return finalizer.privateKeyParameters;
		}

		PrivateKey(McEliecePrivateKeyParameters privateKeyParameters) {
			if (privateKeyParameters==null)
				throw new NullPointerException();
			finalizer=new PrivateKeyFinalizer(this);
			this.finalizer.privateKeyParameters = privateKeyParameters;
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
				return com.distrimind.bouncycastle.util.Arrays.constantTimeAreEqual(getEncoded(), ((PrivateKey) o).getEncoded());
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

			out.writeBytesArray(finalizer.privateKeyParameters.getField().getEncoded(), false, Short.MAX_VALUE);
			out.writeBytesArray(finalizer.privateKeyParameters.getGoppaPoly().getEncoded(), false, Short.MAX_VALUE);
			out.writeBytesArray(finalizer.privateKeyParameters.getH().getEncoded(), false, MAX_GF2MATRIX_SIZE);
			out.writeBytesArray(finalizer.privateKeyParameters.getP1().getEncoded(), false, Short.MAX_VALUE);
			out.writeBytesArray(finalizer.privateKeyParameters.getP2().getEncoded(), false, Short.MAX_VALUE);
			out.writeBytesArray(finalizer.privateKeyParameters.getSInv().getEncoded(), false, MAX_GF2MATRIX_SIZE);
			PolynomialGF2mSmallM[] qinv=finalizer.privateKeyParameters.getQInv();
			if (qinv.length>Short.MAX_VALUE)
				throw new IOException();
			out.writeShort(qinv.length);
			for (PolynomialGF2mSmallM polynomialGF2mSmallM : qinv)
				out.writeBytesArray(polynomialGF2mSmallM.getEncoded(), false, Short.MAX_VALUE);
			out.writeInt(finalizer.privateKeyParameters.getK());
			out.writeInt(finalizer.privateKeyParameters.getN());
		}

		@Override
		public void readExternal(SecuredObjectInputStream in) throws IOException {
			try {
				finalizer.performCleanup();
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
				finalizer.privateKeyParameters=new McEliecePrivateKeyParameters(n, k, field, goppaPoly, sinv, p1, p2, h, qinv);
			}
			catch(Exception e)
			{
				throw new IOException(e);
			}
		}


	}
	private static final class PrivateKeyCAA2Finalizer extends Cleanable.Cleaner
	{
		private McElieceCCA2PrivateKeyParameters privateKeyParameters;

		private PrivateKeyCAA2Finalizer(Cleanable cleanable) {
			super(cleanable);
		}

		@Override
		protected void performCleanup() {
			if (privateKeyParameters!=null)
			{
				for (int[] a : privateKeyParameters.getH().getIntArray())
					Arrays.fill(a, 0);
			}
		}
	}
	static class PrivateKeyCCA2 implements AsymmetricPrivateKey, SecureExternalizableWithoutInnerSizeControl, AutoZeroizable {
		private final PrivateKeyCAA2Finalizer finalizer;
		private volatile byte []encoded=null;
		private volatile Integer hashCode=null;

		public McElieceCCA2PrivateKeyParameters getPrivateKeyParameters() {
			return finalizer.privateKeyParameters;
		}

		PrivateKeyCCA2()
		{
			finalizer=new PrivateKeyCAA2Finalizer(this);
			finalizer.privateKeyParameters=null;
		}

		PrivateKeyCCA2(McElieceCCA2PrivateKeyParameters privateKeyParameters) {
			if (privateKeyParameters==null)
				throw new NullPointerException();
			this.finalizer=new PrivateKeyCAA2Finalizer(this);
			this.finalizer.privateKeyParameters = privateKeyParameters;
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
				return com.distrimind.bouncycastle.util.Arrays.constantTimeAreEqual(getEncoded(), ((PrivateKeyCCA2) o).getEncoded());
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


		public void writeExternal(SecuredObjectOutputStream out, boolean writeDigest) throws IOException {

			out.writeBytesArray(finalizer.privateKeyParameters.getField().getEncoded(), false, Short.MAX_VALUE);
			out.writeBytesArray(finalizer.privateKeyParameters.getGoppaPoly().getEncoded(), false, Short.MAX_VALUE);
			out.writeBytesArray(finalizer.privateKeyParameters.getH().getEncoded(), false, MAX_GF2MATRIX_SIZE);
			out.writeBytesArray(finalizer.privateKeyParameters.getP().getEncoded(), false, Short.MAX_VALUE);
			if (writeDigest)
				out.writeString(finalizer.privateKeyParameters.getDigest(), false, 512);
			out.writeInt(finalizer.privateKeyParameters.getK());
			out.writeInt(finalizer.privateKeyParameters.getN());
		}
		@Override
		public void readExternal(SecuredObjectInputStream in) throws IOException {
			readExternal(in, (String)null);
		}
		public void readExternal(SecuredObjectInputStream in, ASymmetricEncryptionType type) throws IOException {
			String digest;
			finalizer.performCleanup();
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

				finalizer.privateKeyParameters=new McElieceCCA2PrivateKeyParameters(n, k, field, goppaPoly, h, p, digest);

			}
			catch(Exception e)
			{
				throw new IOException(e);
			}
		}
	}

	static class PublicKey implements AsymmetricPublicKey, SecureExternalizableWithoutInnerSizeControl, Zeroizable {
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
				return com.distrimind.bouncycastle.util.Arrays.constantTimeAreEqual(getEncoded(), ((PublicKey) o).getEncoded());
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
		public void clean()
		{
			if (publicKeyParameters!=null)
			{
				for (int[] a : publicKeyParameters.getG().getIntArray())
					Arrays.fill(a, 0);
				publicKeyParameters=null;
			}
		}
		@Override
		public boolean isDestroyed() {
			return publicKeyParameters==null;
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

	static class PublicKeyCCA2 implements AsymmetricPublicKey, SecureExternalizableWithoutInnerSizeControl, Zeroizable {
		private McElieceCCA2PublicKeyParameters publicKeyParameters;
		private volatile byte []encoded=null;
		private volatile Integer hashCode=null;

		public McElieceCCA2PublicKeyParameters getPublicKeyParameters() {
			return publicKeyParameters;
		}

		public PublicKeyCCA2() {
			publicKeyParameters=null;
		}
		@Override
		public void clean()
		{
			if (publicKeyParameters!=null)
			{
				for (int[] a : publicKeyParameters.getG().getIntArray())
					Arrays.fill(a, 0);
				publicKeyParameters=null;
			}
		}
		@Override
		public boolean isDestroyed() {
			return publicKeyParameters==null;
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
				return com.distrimind.bouncycastle.util.Arrays.constantTimeAreEqual(getEncoded(), ((PublicKeyCCA2) o).getEncoded());
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
		private long publicKeyValidityBeginDateUTC;

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
					new ASymmetricPublicKey(encryptionType, new PublicKey((McEliecePublicKeyParameters) res.getPublic()), keySize, publicKeyValidityBeginDateUTC, keyExpiration));
		}

		@Override
		public String getAlgorithm() {
			return encryptionType.getAlgorithmName();
		}

		@Override
		public void initialize(int keySize, long publicKeyValidityBeginDateUTC, long expirationTime) throws IOException {
			try {
				initialize(keySize, publicKeyValidityBeginDateUTC, expirationTime, SecureRandomType.BC_FIPS_APPROVED_FOR_KEYS.getSingleton(null));
			} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
				throw new IOException(e);
			}
		}

		@Override
		public void initialize(int keySize, long publicKeyValidityBeginDateUTC, long expirationTime, AbstractSecureRandom random) {
			this.keySize= keySize;
			this.keyExpiration=expirationTime;
			this.publicKeyValidityBeginDateUTC=publicKeyValidityBeginDateUTC;
			mcElieceKeyPairGenerator=new McElieceKeyPairGenerator();
			mcElieceKeyPairGenerator.init(new McElieceKeyGenerationParameters(random, new McElieceParameters(getDigest())));
		}
	}

	static class KeyPairGeneratorCCA2 extends AbstractKeyPairGenerator
	{
		private McElieceCCA2KeyPairGenerator mcElieceKeyPairGenerator=null;

		private final String digest;
		private int keySize;
		private long keyExpiration;
		private long publicKeyValidityBeginDateUTC;

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
					new ASymmetricPublicKey(encryptionType, new PublicKeyCCA2((McElieceCCA2PublicKeyParameters) res.getPublic()), keySize, publicKeyValidityBeginDateUTC, keyExpiration));
		}

		@Override
		public String getAlgorithm() {
			return encryptionType.getAlgorithmName();
		}

		@Override
		public void initialize(int keySize,long publicKeyValidityBeginDateUTC, long expirationTime) throws IOException {
			try {
				initialize(keySize, publicKeyValidityBeginDateUTC, expirationTime, SecureRandomType.BC_FIPS_APPROVED_FOR_KEYS.getSingleton(null));
			} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
				throw new IOException(e);
			}
		}

		@Override
		public void initialize(int keySize, long publicKeyValidityBeginDateUTC, long expirationTime, AbstractSecureRandom random) {
			this.keySize= keySize;
			this.keyExpiration=expirationTime;
			this.publicKeyValidityBeginDateUTC=publicKeyValidityBeginDateUTC;
			mcElieceKeyPairGenerator=new McElieceCCA2KeyPairGenerator();
			mcElieceKeyPairGenerator.init(new McElieceCCA2KeyGenerationParameters(random, new McElieceCCA2Parameters(digest)));
		}
	}

	@Override
	public byte[] doFinal() throws IOException {
		try {
			byte[] b = out.toByteArray();
			if (encrypt) {
				return mcElieceCipher.messageEncrypt(b);
			} else {
				try {
					return mcElieceCipher.messageDecrypt(b);
				} catch (InvalidCipherTextException e) {
					throw new IllegalStateException(e);
				}
			}
		}
		finally {
			out.reset();
		}
	}

	@Override
	public int doFinal(byte[] output, int outputOffset) throws IOException {
		byte[] res=doFinal();
		System.arraycopy(res, 0, output, outputOffset, res.length);
		return res.length;
	}

	@Override
	public byte[] doFinal(byte[] input, int inputOffset, int inputLength) throws IOException {
		update(input, inputOffset, inputLength);
		return doFinal();
	}

	@Override
	public int doFinal(byte[] input, int inputOffset, int inputLength, byte[] output, int outputOffset) throws IOException {
		update(input, inputOffset, inputLength, output, outputOffset);
		return doFinal(output, outputOffset);
	}

	@Override
	public String getAlgorithm() {
		return encryptionType.getAlgorithmName();
	}

	@Override
	public int getBlockSize() {
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
					data=doFinal(out.toByteArray());

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
			private final ByteArrayOutputStream buf=new ByteArrayOutputStream();
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
				byte[] res=doFinal(buf.toByteArray());
				out.write(res);
			}
		};
	}

	@Override
	public byte[] getIV() {
		return null;
	}

	@Override
	protected int getOutputSize(int inputLength) throws IllegalStateException {

		return inputLength;
	}
	@Override
	public void init(int opMode, AbstractKey key) throws IOException {
		init(opMode, key, (AbstractSecureRandom)null);
	}
	@Override
	public void init(int opMode, AbstractKey key, AbstractSecureRandom random) throws IOException {
		mode= opMode;
		out.reset();
		encrypt= opMode == Cipher.ENCRYPT_MODE || opMode ==Cipher.WRAP_MODE;
		mcElieceCipher=getMcElieceCipher();
		try {
			if (cca2) {
				if (key instanceof ASymmetricPrivateKey) {
					mcElieceCipher.init(encrypt, ((PrivateKeyCCA2) key.toBouncyCastleKey()).finalizer.privateKeyParameters);
				} else {

					mcElieceCipher.init(encrypt, new ParametersWithRandom(((PublicKeyCCA2) key.toBouncyCastleKey()).publicKeyParameters, random));
				}
			} else {

				if (key instanceof ASymmetricPrivateKey) {
					mcElieceCipher.init(encrypt, ((PrivateKey) key.toBouncyCastleKey()).finalizer.privateKeyParameters);
				} else {
					mcElieceCipher.init(encrypt, new ParametersWithRandom(((PublicKey) key.toBouncyCastleKey()).publicKeyParameters));
				}
			}
		} catch (NoSuchAlgorithmException e) {
			throw new IOException(e);
		} catch (InvalidKeySpecException e) {
			throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN);
		}

	}

	@Override
	public void init(int opMode, AbstractKey key, byte[] iv) throws IOException {
		mode= opMode;
		try {
			init(opMode, key, SecureRandomType.BC_FIPS_APPROVED_FOR_KEYS.getSingleton(null));
		} catch (NoSuchProviderException | NoSuchAlgorithmException e) {
			throw new IOException(e);
		}
	}

	@Override
	public byte[] update(byte[] input, int inputOffset, int inputLength) throws IllegalStateException {
		out.write(input, inputOffset, inputLength);
		return empty;
	}
	private final byte[] empty=new byte[0];

	@Override
	public int update(byte[] input, int inputOffset, int inputLength, byte[] output, int outputOffset) throws IOException {
		out.write(input, inputOffset, inputLength);
		return 0;
	}

	@Override
	public void updateAAD(byte[] ad, int offset, int size) {

	}
}

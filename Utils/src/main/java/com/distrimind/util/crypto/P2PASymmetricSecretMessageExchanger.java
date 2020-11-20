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

import com.distrimind.util.data_buffers.WrappedData;
import com.distrimind.util.io.Integrity;
import com.distrimind.util.io.MessageExternalizationException;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Random;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;


/**
 * 
 * @author Jason Mahdjoub
 * @version 4.1
 * @since Utils 1.4.1
 */
public class P2PASymmetricSecretMessageExchanger {
	static class FakeSecureRandom extends AbstractSecureRandom {

		/**
		 * 
		 */
		private static final long serialVersionUID = -3862260428441022619L;

		private volatile Object gnuRandom=null;

		protected FakeSecureRandom() {
			
			super(new AbstractSecureRandomSpi(false) {
				/**
				 * 
				 */
				private static final long serialVersionUID = 6035266817848199010L;
				final Random random = new Random();
				
				@Override
				protected void engineSetSeed(byte[] seed) {
					if (random!=null)
					{
						byte[] s = new byte[seed.length + 1];
						s[0]=1;
						System.arraycopy(seed, 0, s, 0, seed.length);
						BigInteger num = new BigInteger(s);
						random.setSeed(num.mod(maxLongValue).longValue());
					}
					
				}
				
				@Override
				protected void engineNextBytes(byte[] bytes) {
					random.nextBytes(bytes);					
				}
				
				@Override
				protected byte[] engineGenerateSeed(int numBytes) {
					return null;
				}
			}, null);



		}

		@Override
		public String getAlgorithm() {
			return "Fake Secure Random";
		}

		@Override
		public Object getGnuSecureRandom() {
			if (gnuRandom==null)
				gnuRandom=GnuFunctions.getGnuRandomInterface(secureRandomSpi);
			return gnuRandom;
		}

		@Override
		public java.security.SecureRandom getJavaNativeSecureRandom() {
			return this;
		}

		@Override
		void setSeed(byte[] seed, boolean mixWithPreviousSeed) {
			super.unmodifiedSetSeed(seed);
		}

		@Override
		public void setSeed(byte[] seed) {
			super.unmodifiedSetSeed(seed);
		}
	}

	protected static final BigInteger maxLongValue = BigInteger.valueOf(1).shiftLeft(63);

	private static AbstractCipher getCipherInstancePrivate(ASymmetricEncryptionType type)
			throws NoSuchAlgorithmException, NoSuchProviderException, MessageExternalizationException {
		return type.getCipherInstance();
	}

	private final ASymmetricPublicKey myPublicKey;

	private P2PASymmetricSecretMessageExchanger distantMessageEncoder;

	private final AbstractSecureRandom random;
	
	private final AbstractSecureRandom secureRandom; 

	private final AbstractCipher cipher;

	private final AbstractMessageDigest messageDigest, messageDigest256;

	private final MessageDigestType messageDigestType;

	private final PasswordHashType passwordHashType;

	private byte cost = PasswordHash.DEFAULT_COST;

	P2PASymmetricSecretMessageExchanger(AbstractSecureRandom secureRandom, ASymmetricPublicKey myPublicKey)
			throws NoSuchAlgorithmException, NoSuchProviderException, MessageExternalizationException {
		this(secureRandom, MessageDigestType.BC_FIPS_SHA3_512, PasswordHashType.BC_FIPS_PBKFD2WithHMacSHA2_512, myPublicKey);
	}

	P2PASymmetricSecretMessageExchanger(AbstractSecureRandom secureRandom, MessageDigestType messageDigestType, PasswordHashType passwordHashType,
			ASymmetricPublicKey myPublicKey) throws NoSuchAlgorithmException, NoSuchProviderException, MessageExternalizationException {
		this(secureRandom, messageDigestType, passwordHashType, myPublicKey, null);
	}

	P2PASymmetricSecretMessageExchanger(AbstractSecureRandom secureRandom, MessageDigestType messageDigestType, PasswordHashType passwordHashType,
			ASymmetricPublicKey myPublicKey, byte[] distantPublicKey)
			throws NoSuchAlgorithmException, NoSuchProviderException, MessageExternalizationException {
		if (messageDigestType == null)
			throw new NullPointerException("messageDigestType");
		if (myPublicKey == null)
			throw new NullPointerException("myPublicKey");
		if (passwordHashType == null)
			throw new NullPointerException("passwordHashType");
		if (secureRandom==null)
			throw new NullPointerException("secureRandom");
		ASymmetricEncryptionType type = myPublicKey.getEncryptionAlgorithmType();
		this.myPublicKey = myPublicKey;
		this.secureRandom=secureRandom;

		if (distantPublicKey != null)
			setDistantPublicKey(distantPublicKey);
		random = new FakeSecureRandom();
		cipher = getCipherInstancePrivate(type);
		this.messageDigestType = messageDigestType;
		this.messageDigest = messageDigestType.getMessageDigestInstance();
		this.messageDigest.reset();
		this.passwordHashType = passwordHashType;
		this.messageDigest256 = MessageDigestType.BC_FIPS_SHA3_256.getMessageDigestInstance();
	}

	public byte[] encode(byte[] message, byte[] salt, boolean messageIsKey) throws IOException, InvalidKeyException,
			IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException,
			NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchProviderException, IllegalStateException {
		if (salt == null)
			salt = new byte[0];
		return encode(message, 0, message.length, salt, 0, salt.length, messageIsKey);
	}

	public byte[] encode(byte[] message, int offset, int len, byte[] salt, int offset_salt, int len_salt,
			boolean messageIsKey) throws IOException, InvalidKeyException, IllegalBlockSizeException,
			BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException,
			InvalidAlgorithmParameterException, NoSuchProviderException, IllegalStateException {
		if (message == null)
			throw new NullPointerException("message");
		if (message.length - offset < len)
			throw new IllegalArgumentException("message");
		if (salt != null && salt.length - offset_salt < len_salt)
			throw new IllegalArgumentException("salt");

		message = hashMessage(messageDigest, message, offset, len, salt, offset_salt, len_salt, messageIsKey);
		byte[] encodedLevel2 = encodeLevel2(message);
		byte[] res=encodeLevel1(encodedLevel2, message, salt, offset_salt, len_salt);
		Arrays.fill(message, (byte)0);
		Arrays.fill(encodedLevel2, (byte)0);
		return res;
	}

	private byte[] encodeLevel2(byte[] hashedMessage)
			throws IOException{
		initCipherForEncrypt(hashedMessage);

		int maxBlockSize = myPublicKey.getMaxBlockSize();

		boolean finish = false;
		int offset = 0;
		try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
			while (!finish) {

				int size = Math.min(maxBlockSize, hashedMessage.length - offset);
				if (size > 0) {
					baos.write(cipher.doFinal(hashedMessage, offset, size));
					offset += size;
				}
				if (size <= 0)
					finish = true;
			}
			baos.flush();
			return baos.toByteArray();
		}
	}

	private byte[] encodeLevel1(byte[] encodedLevel2, byte[] hashedMessage, byte[] salt, int offset_salt, int len_salt)
			throws IOException {
		try {
			hashedMessage = hashMessage(messageDigest256, hashedMessage, 0, hashedMessage.length, salt, offset_salt,
					len_salt, false);

			SymmetricEncryptionAlgorithm sea = new SymmetricEncryptionAlgorithm(secureRandom,
					new SymmetricSecretKey(SymmetricEncryptionType.BC_FIPS_AES_GCM,
							new SecretKeySpec(hashedMessage,
									SymmetricEncryptionType.BC_FIPS_AES_GCM.getAlgorithmName()),
							(short) 256));
			byte[] res = sea.encode(OutputDataPackagerWithRandomValues.encode(encodedLevel2, encodedLevel2.length));
			Arrays.fill(hashedMessage, (byte) 0);
			return res;
		}
		catch (NoSuchAlgorithmException | NoSuchProviderException e) {
			throw new MessageExternalizationException(Integrity.FAIL, e);
		}
	}

	private byte[] decodeLevel2(byte[] encodedLevel1, int off_encodedlevel1, int len_encodedlevel1,
								byte[] hashedMessage, byte[] salt, int offset_salt, int len_salt)
			throws IOException {

		hashedMessage = hashMessage(messageDigest256, hashedMessage, 0, hashedMessage.length, salt, offset_salt,
				len_salt, false);

		SymmetricEncryptionAlgorithm sea = new SymmetricEncryptionAlgorithm(secureRandom,
				new SymmetricSecretKey(SymmetricEncryptionType.BC_FIPS_AES_GCM,
						new SecretKeySpec(hashedMessage,
								SymmetricEncryptionType.BC_FIPS_AES_GCM.getAlgorithmName()),
						(short) 256));
		byte[] v = sea.decode(encodedLevel1, off_encodedlevel1, len_encodedlevel1);
		try {
			return InputDataPackagedWithRandomValues.decode(v);
		} catch (Throwable e) {
			return null;
		} finally {
			Arrays.fill(v, (byte) 0);
			Arrays.fill(hashedMessage, (byte) 0);
		}
	}

	public byte[] encode(char[] message, byte[] salt) throws IOException, InvalidKeyException,
			IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException,
			NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchProviderException, IllegalStateException {
		if (salt == null)
			salt = new byte[0];
		return encode(message, salt, 0, salt.length);
	}

	public byte[] encode(char[] message, byte[] salt, int offset_salt, int len_salt)
			throws IOException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException,
			NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException,
			InvalidAlgorithmParameterException, NoSuchProviderException, IllegalStateException {
		if (message == null)
			throw new NullPointerException("message");
		if (salt == null) {
			salt = new byte[0];
			offset_salt = 0;
			len_salt = 0;
		}
		if (salt.length - offset_salt < len_salt)
			throw new IllegalArgumentException("salt");

		byte[] hashedMessage = hashMessage(messageDigest, message, salt, offset_salt, len_salt);
		byte[] encodedLevel2 = encodeLevel2(hashedMessage);
		byte[] res=encodeLevel1(encodedLevel2, hashedMessage, salt, offset_salt, len_salt);
		Arrays.fill(hashedMessage, (byte)0);
		Arrays.fill(encodedLevel2, (byte)0);
		return res;
	}

	public byte[] encode(String message, byte[] salt) throws IOException, InvalidKeyException,
			IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException,
			NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchProviderException, IllegalStateException {
		return encode(message.toCharArray(), salt);
	}

	public byte[] encode(String message, byte[] salt, int offset_salt, int len_salt)
			throws IOException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException,
			NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException,
			InvalidAlgorithmParameterException, NoSuchProviderException, IllegalStateException {
		return encode(message.toCharArray(), salt, offset_salt, len_salt);
	}

	public WrappedData encodeMyPublicKey() {
		return myPublicKey.encode();
	}

	public ASymmetricPublicKey getDistantPublicKey() {
		if (distantMessageEncoder == null)
			return null;
		return this.distantMessageEncoder.getMyPublicKey();
	}

	public byte getCost() {
		return cost;
	}

	public ASymmetricPublicKey getMyPublicKey() {
		return myPublicKey;
	}

	private byte[] hashMessage(AbstractMessageDigest messageDigest, byte[] data, int off, int len, byte[] salt,
							   int offset_salt, int len_salt, boolean messageIsKey)
			throws IOException {
		boolean zeroize=false;
		if (!messageIsKey && salt != null && len_salt > 0) {
			byte[] s = new byte[len_salt];
			System.arraycopy(salt, offset_salt, s, 0, len_salt);
			data = passwordHashType.hash(data, off, len, s, cost, passwordHashType.getDefaultHashLengthBytes());
			off = 0;
			assert data != null;
			len = data.length;
			zeroize=true;
		}
		messageDigest.update(data, off, len);
		if (messageIsKey && salt != null && len_salt > 0)
			messageDigest.update(salt, offset_salt, len_salt);
		byte[] res=messageDigest.digest();
		if (zeroize)
			Arrays.fill(data, (byte)0);
		return res;
	}

	private byte[] hashMessage(AbstractMessageDigest messageDigest, char[] password, byte[] salt, int offset_salt,
							   int len_salt) throws IOException {
		if (salt == null)
			throw new NullPointerException(
					"salt can't be null when the message is a password (and not a secret key) !");
		if (salt.length == 0)
			throw new NullPointerException(
					"salt can't be empty when the message is a password (and not a secret key) !");

		if (len_salt > 0) {
			byte[] s = new byte[len_salt];
			System.arraycopy(salt, offset_salt, s, 0, len_salt);
			byte[] res = passwordHashType.hash(password, s, cost, passwordHashType.getDefaultHashLengthBytes());

			byte[] r2=hashMessage(messageDigest, res, 0, res.length, null, -1, -1, true);
			Arrays.fill(res, (byte)0);
			return r2;
		} else {
			byte[] res = new byte[password.length * 2];
			for (int i = 0; i < password.length; i++) {
				res[i * 2] = (byte) (password[i] & 0xFF);
				res[i * 2 + 1] = (byte) ((password[i] >> 8) & 0xFF);
			}
			byte[] r2=hashMessage(messageDigest, res, 0, res.length, null, -1, -1, true);
			Arrays.fill(res, (byte)0);
			return r2;
		}

	}

	private void initCipherForEncrypt(byte[] hashedMessage)
			throws IOException {
		random.setSeed(hashedMessage);
		cipher.init(Cipher.ENCRYPT_MODE, myPublicKey, random);
		messageDigest.reset();
	}

	public void setDistantPublicKey(byte[] distantPublicKeyAndIV)
			throws NoSuchAlgorithmException, NoSuchProviderException, MessageExternalizationException {
		distantMessageEncoder = new P2PASymmetricSecretMessageExchanger(secureRandom, messageDigestType, passwordHashType,
				(ASymmetricPublicKey) AbstractKey.decode(distantPublicKeyAndIV));
		if (myPublicKey.equals(distantMessageEncoder.myPublicKey))
			throw new IllegalArgumentException("Local public key equals distant public key");
		distantMessageEncoder.setCost(getCost());
	}

	public void setCost(byte cost) {
		if (cost<4 || cost>31)
			throw new IllegalArgumentException("cost must be greater or equals than 4 and lower or equals than 31");

		this.cost = cost;
		if (distantMessageEncoder != null)
			distantMessageEncoder.setCost(cost);
	}

	public boolean verifyDistantMessage(byte[] originalMessage, byte[] salt, byte[] distantMessage,
			boolean messageIsKey) throws IOException {
		if (salt == null)
			salt = new byte[0];
		return this.verifyDistantMessage(originalMessage, 0, originalMessage.length, salt, 0, salt.length,
				distantMessage, 0, distantMessage.length, messageIsKey);
	}

	public boolean verifyDistantMessage(byte[] originalMessage, int offo, int leno, byte[] salt, int offset_salt,
			int len_salt, byte[] distantMessage, int offd, int lend, boolean messageIsKey)
			throws IOException {
		if (originalMessage == null)
			throw new NullPointerException("message");
		if (originalMessage.length - offo < leno)
			throw new IllegalArgumentException("message");
		if (distantMessage == null)
			throw new NullPointerException("distantMessage");
		if (distantMessage.length - offd < lend)
			throw new IllegalArgumentException("distantMessage");
		if (salt == null) {
			salt = new byte[0];
			offset_salt = 0;
			len_salt = 0;
		}
		if (salt.length - offset_salt < len_salt)
			throw new IllegalArgumentException("salt");

		if (distantMessageEncoder == null)
			throw new MessageExternalizationException(Integrity.FAIL, new IllegalAccessException("You must set the distant public key before calling this function ! "));

		byte[] hashedMessage = distantMessageEncoder.hashMessage(messageDigest, originalMessage, offo, leno, salt,
				offset_salt, len_salt, messageIsKey);
		byte[] encodedLevel2 = distantMessageEncoder.encodeLevel2(hashedMessage);
		try {
			byte[] distantLevel2 = distantMessageEncoder.decodeLevel2(distantMessage, offd, lend, hashedMessage, salt,
					offset_salt, len_salt);

			return compareEncodedLevel2(encodedLevel2, distantLevel2);
		} catch (Throwable e) {
			return false;
		}


	}

	private boolean compareEncodedLevel2(byte[] encodedLevel2, byte[] distantLevel2) {
		if (distantLevel2 == null)
			return false;
		if (encodedLevel2.length != distantLevel2.length)
			return false;
		for (int i = 0; i < encodedLevel2.length; i++) {
			if (encodedLevel2[i] != distantLevel2[i])
				return false;
		}
		return true;
	}

	public boolean verifyDistantMessage(char[] originalMessage, byte[] salt, byte[] distantMessage)
			throws IOException{
		if (salt == null)
			salt = new byte[0];
		return this.verifyDistantMessage(originalMessage, salt, 0, salt.length, distantMessage, 0,
				distantMessage.length);
	}

	public boolean verifyDistantMessage(char[] originalMessage, byte[] salt, int offset_salt, int len_salt,
			byte[] distantMessage, int offd, int lend)
			throws IOException {
		if (originalMessage == null)
			throw new NullPointerException("message");
		if (distantMessage == null)
			throw new NullPointerException("distantMessage");
		if (distantMessage.length - offd < lend)
			throw new IllegalArgumentException("distantMessage");
		if (salt == null) {
			salt = new byte[0];
			offset_salt = 0;
			len_salt = 0;
		}
		if (salt.length - offset_salt < len_salt)
			throw new IllegalArgumentException("salt");

		if (distantMessageEncoder == null)
			throw new MessageExternalizationException(Integrity.FAIL, new IllegalAccessException("You must set the distant public key before calling this function ! "));

		byte[] hashedMessage = distantMessageEncoder.hashMessage(messageDigest, originalMessage, salt, offset_salt,
				len_salt);
		byte[] encodedLevel2 = distantMessageEncoder.encodeLevel2(hashedMessage);
		try {
			byte[] distantLevel2 = distantMessageEncoder.decodeLevel2(distantMessage, offd, lend, hashedMessage, salt,
					offset_salt, len_salt);

			boolean res = compareEncodedLevel2(encodedLevel2, distantLevel2);
			assert distantLevel2 != null;
			Arrays.fill(distantLevel2, (byte) 0);
			return res;
		} catch (Throwable e) {
			return false;
		} finally {
			Arrays.fill(hashedMessage, (byte) 0);
			Arrays.fill(encodedLevel2, (byte) 0);

		}
	}

	public boolean verifyDistantMessage(String originalMessage, byte[] salt, byte[] distantMessage)
			throws IOException {
		return this.verifyDistantMessage(originalMessage.toCharArray(), salt, distantMessage);
	}

}

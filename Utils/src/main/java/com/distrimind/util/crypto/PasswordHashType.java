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

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import com.distrimind.util.OSVersion;
import com.distrimind.util.io.Integrity;
import com.distrimind.util.io.MessageExternalizationException;
import com.distrimind.bcfips.crypto.PasswordBasedDeriver;
import com.distrimind.bcfips.crypto.PasswordConverter;
import com.distrimind.bcfips.crypto.fips.FipsDigestAlgorithm;
import com.distrimind.bcfips.crypto.fips.FipsPBKD;
import com.distrimind.bcfips.crypto.fips.FipsSHS;
import com.distrimind.bouncycastle.crypto.generators.BCrypt;
import com.distrimind.bouncycastle.crypto.generators.SCrypt;

import com.distrimind.util.Bits;
import com.distrimind.util.OS;
import com.distrimind.util.sizeof.ObjectSizer;


/**
 * 
 * @author Jason Mahdjoub
 * @version 3.0
 * @since Utils 1.8
 *
 */
public enum PasswordHashType {
	PBKDF2WithHmacSHA1("PBKDF2WithHmacSHA1", (byte) 32, CodeProvider.SunJCE, (byte)1),
	PBKDF2WithHMacSHA2_256("PBKDF2WithHMacSHA256", (byte) 32, CodeProvider.SunJCE, (byte)2),
	PBKDF2WithHMacSHA2_384("PBKDF2WithHMacSHA384", (byte) 32, CodeProvider.SunJCE, (byte)3),
	PBKDF2WithHMacSHA2_512("PBKDF2WithHMacSHA512", (byte) 32, CodeProvider.SunJCE, (byte)4),
	BC_BCRYPT("BC_BCRYPT", (byte) 24, CodeProvider.SUN, (byte)5),
	BC_SCRYPT_FOR_LOGIN("SCRYPT", (byte)32, CodeProvider.BC, (byte)6),
	BC_SCRYPT_FOR_DATA_ENCRYPTION("SCRYPT", (byte)32, CodeProvider.BC, (byte)7),
	GNU_PBKDF2WithHmacSHA1("PBKDF2WithHMacSHA1", (byte) 32, CodeProvider.GNU_CRYPTO, (byte)8), 
	GNU_PBKDF2WithHMacSHA2_256("PBKDF2WithHMacSHA256",(byte) 32, CodeProvider.GNU_CRYPTO, (byte)9),
	GNU_PBKDF2WithHMacSHA2_384("PBKDF2WithHMacSHA384", (byte) 32, CodeProvider.GNU_CRYPTO, (byte)10),
	GNU_PBKDF2WithHMacSHA2_512("PBKDF2WithHMacSHA512", (byte) 32, CodeProvider.GNU_CRYPTO, (byte)11),
	GNU_PBKDF2WithHMacWhirlpool("PBKDF2WithHMacWhirlpool",(byte) 32, CodeProvider.GNU_CRYPTO, (byte)12),
	BC_FIPS_PBKFD2WithHMacSHA2_256("PBKDF2WithHMacSHA2_256",(byte) 32, CodeProvider.BCFIPS, FipsSHS.Algorithm.SHA256_HMAC, (byte)13),
	BC_FIPS_PBKFD2WithHMacSHA2_384("PBKDF2WithHMacSHA2_384",(byte) 32, CodeProvider.BCFIPS, FipsSHS.Algorithm.SHA384_HMAC, (byte)14),
	BC_FIPS_PBKFD2WithHMacSHA2_512("PBKDF2WithHMacSHA2_512",(byte) 32, CodeProvider.BCFIPS, FipsSHS.Algorithm.SHA512_HMAC, (byte)15),
	DEFAULT(BC_BCRYPT);

	
		
	
	private final byte hashLength;

	private PasswordHashType defaultOf;

	private final String algorithmName;
	
	private final CodeProvider codeProvider;
	
	private final FipsDigestAlgorithm fipsDigestAlgorithm;
	
	private final byte id;

	public boolean equals(PasswordHashType type)
	{
		if (type==null)
			return false;
		//noinspection StringEquality
		return type.algorithmName==this.algorithmName && type.codeProvider==this.codeProvider;
	}

	PasswordHashType(PasswordHashType type) {
		this(type.algorithmName, type.hashLength, type.codeProvider, type.fipsDigestAlgorithm, type.id);
		this.defaultOf = type;
	}

	PasswordHashType(String algorithmName, byte hashLength, CodeProvider codeProvider, FipsDigestAlgorithm fipsDigestAlgorithm, byte id) {
		this.hashLength = hashLength;
		this.defaultOf = null;
		this.algorithmName = algorithmName;
		this.codeProvider=codeProvider;
		this.fipsDigestAlgorithm=fipsDigestAlgorithm;
		this.id=id;
	}
	PasswordHashType(String algorithmName, byte hashLength, CodeProvider codeProvider, byte id) {
		this(algorithmName, hashLength, codeProvider, null, id);
	}
	
	byte getID()
	{
		return id;
	}
	
	public CodeProvider getCodeProvider()
	{
		return codeProvider;
	}
	public byte getDefaultHashLengthBytes()
	{
		return hashLength;
	}
	@SuppressWarnings("fallthrough")
	byte[] hash(byte[] data, int off, int len, byte[] salt, byte cost, byte hashLength)
			throws IOException {
		try {
			CodeProvider.ensureProviderLoaded(codeProvider);
			if (cost < 4 || cost > 31)
				throw new IllegalArgumentException("cost must be greater or equals than 4 and lower or equals than 31");

			if (defaultOf != null)
				return defaultOf.hash(data, off, len, salt, cost, hashLength);

			if (OSVersion.getCurrentOSVersion() != null && OSVersion.getCurrentOSVersion().getOS() == OS.MAC_OS_X) {
				if (this == PBKDF2WithHMacSHA2_256)
					return PasswordHashType.BC_FIPS_PBKFD2WithHMacSHA2_256.hash(data, off, len, salt, cost, hashLength);
				if (this == PBKDF2WithHMacSHA2_384)
					return PasswordHashType.BC_FIPS_PBKFD2WithHMacSHA2_384.hash(data, off, len, salt, cost, hashLength);
				if (this == PBKDF2WithHMacSHA2_512)
					return PasswordHashType.BC_FIPS_PBKFD2WithHMacSHA2_512.hash(data, off, len, salt, cost, hashLength);
			}
			int scryptN = 1 << 18;
			int iterations = 1 << (cost - 1);
			switch (this) {
				case DEFAULT:
				case PBKDF2WithHmacSHA1:
				case PBKDF2WithHMacSHA2_256:
				case PBKDF2WithHMacSHA2_384:
				case PBKDF2WithHMacSHA2_512: {
					int size = len / 2;
					char[] password = new char[size + len % 2];
					for (int i = 0; i < size; i++) {
						password[i] = (char) ((data[off + i * 2] & 0xFF) & ((data[off + i * 2 + 1] << 8) & 0xFF));
					}
					if (size < password.length)
						password[size] = (char) (data[off + size * 2] & 0xFF);

					PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, (hashLength) * 8);
					SecretKeyFactory skf = SecretKeyFactory.getInstance(algorithmName, codeProvider.checkProviderWithCurrentOS().name());
					return skf.generateSecret(spec).getEncoded();
				}
				case GNU_PBKDF2WithHMacSHA2_256:
				case GNU_PBKDF2WithHMacSHA2_384:
				case GNU_PBKDF2WithHMacSHA2_512:
				case GNU_PBKDF2WithHMacWhirlpool:
				case GNU_PBKDF2WithHmacSHA1: {
					int size = len / 2;
					char[] password = new char[size + len % 2];
					for (int i = 0; i < size; i++) {
						password[i] = (char) ((data[off + i * 2] & 0xFF) & ((data[off + i * 2 + 1] << 8) & 0xFF));
					}
					if (size < password.length)
						password[size] = (char) (data[off + size * 2] & 0xFF);

					Object spec = GnuFunctions.PBEKeySpecGetInstance(password, salt,
							iterations, (hashLength));
					Object skf = GnuFunctions.secretKeyFactoryGetInstance(algorithmName);
					return GnuFunctions.keyGetEncoded(GnuFunctions.secretKeyFactoryGenerateSecret(skf, spec));
				}
				case BC_BCRYPT: {
					byte[] passwordb;
					boolean fill=false;
					if (off != 0 || len != data.length) {
						passwordb = new byte[len];
						System.arraycopy(data, off, passwordb, 0, len);
						fill=true;
					} else
						passwordb = data;

					salt = uniformizeSaltLength(salt, 16);

					byte[] res= BCrypt.generate(passwordb, salt, cost);
					if (fill)
						Arrays.fill(passwordb, (byte)0);
					return res;
				}
				case BC_FIPS_PBKFD2WithHMacSHA2_256:
				case BC_FIPS_PBKFD2WithHMacSHA2_384:
				case BC_FIPS_PBKFD2WithHMacSHA2_512: {
					PasswordBasedDeriver<com.distrimind.bcfips.crypto.fips.FipsPBKD.Parameters> derivative =
							new FipsPBKD.DeriverFactory().createDeriver(FipsPBKD.PBKDF2.using(fipsDigestAlgorithm, data)
									.withIterationCount(iterations)
									.withSalt(salt));
					return derivative.deriveKey(PasswordBasedDeriver.KeyType.CIPHER, ((hashLength * 8) + 7) / 8);
				}
				case BC_SCRYPT_FOR_LOGIN:

					scryptN = 1 << 13;

				case BC_SCRYPT_FOR_DATA_ENCRYPTION: {
					byte[] d;
					boolean fill=false;
					if (len == data.length && off == 0)
						d = data;
					else {
						d = new byte[len];
						System.arraycopy(data, off, d, 0, len);
						fill=true;
					}
					byte[] res=SCrypt.generate(d, salt, scryptN, 8, 1, hashLength);
					if (fill)
						Arrays.fill(d, (byte)0);
					return res;
				}
				default:
					break;
			}

		} catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException e) {
			throw new MessageExternalizationException(Integrity.FAIL, e);
		}
		throw new InternalError();
	}

	byte[] hash(char[] password, byte[] salt, byte cost, byte hashLength) throws IOException {
		try {
			CodeProvider.ensureProviderLoaded(codeProvider);
			if (cost < 4 || cost > 31)
				throw new IllegalArgumentException("cost must be greater or equals than 4 and lower or equals than 31");

			if (defaultOf != null)
				return defaultOf.hash(password, salt, cost, hashLength);
			if (OSVersion.getCurrentOSVersion() != null && OSVersion.getCurrentOSVersion().getOS() == OS.MAC_OS_X) {
				if (this == PBKDF2WithHMacSHA2_256)
					return PasswordHashType.BC_FIPS_PBKFD2WithHMacSHA2_256.hash(password, salt, cost, hashLength);
				if (this == PBKDF2WithHMacSHA2_384)
					return PasswordHashType.BC_FIPS_PBKFD2WithHMacSHA2_384.hash(password, salt, cost, hashLength);
				if (this == PBKDF2WithHMacSHA2_512)
					return PasswordHashType.BC_FIPS_PBKFD2WithHMacSHA2_512.hash(password, salt, cost, hashLength);
			}
			int iterations = 1 << (cost - 1);
			int scryptN = 1 << 18;
			switch (this) {
				case DEFAULT:
				case PBKDF2WithHmacSHA1:
				case PBKDF2WithHMacSHA2_256:
				case PBKDF2WithHMacSHA2_384:
				case PBKDF2WithHMacSHA2_512: {
					PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, (hashLength) * 8);
					SecretKeyFactory skf = SecretKeyFactory.getInstance(algorithmName, codeProvider.checkProviderWithCurrentOS().name());
					return skf.generateSecret(spec).getEncoded();
				}
				case GNU_PBKDF2WithHMacSHA2_256:
				case GNU_PBKDF2WithHMacSHA2_384:
				case GNU_PBKDF2WithHMacSHA2_512:
				case GNU_PBKDF2WithHMacWhirlpool:
				case GNU_PBKDF2WithHmacSHA1: {
					Object spec = GnuFunctions.PBEKeySpecGetInstance(password, salt,
							iterations, hashLength);
					Object skf = GnuFunctions.secretKeyFactoryGetInstance(algorithmName);
					return GnuFunctions.keyGetEncoded(GnuFunctions.secretKeyFactoryGenerateSecret(skf, spec));
				}
				case BC_BCRYPT: {

					salt = uniformizeSaltLength(salt, 16);
					byte[] t=BCrypt.passwordToByteArray(password);
					byte[] res=BCrypt.generate(t, salt, cost);
					Arrays.fill(t, (byte)0);
					return res;
				}
				case BC_FIPS_PBKFD2WithHMacSHA2_256:
				case BC_FIPS_PBKFD2WithHMacSHA2_384:
				case BC_FIPS_PBKFD2WithHMacSHA2_512: {
					PasswordBasedDeriver<com.distrimind.bcfips.crypto.fips.FipsPBKD.Parameters> derivative =
							new FipsPBKD.DeriverFactory().createDeriver(FipsPBKD.PBKDF2.using(fipsDigestAlgorithm, PasswordConverter.UTF8.convert(password))
									.withIterationCount(iterations)
									.withSalt(salt));
					return derivative.deriveKey(PasswordBasedDeriver.KeyType.CIPHER, ((hashLength * 8) + 7) / 8);
				}
				case BC_SCRYPT_FOR_LOGIN:
					scryptN = 1 << 13;

				case BC_SCRYPT_FOR_DATA_ENCRYPTION:
					byte[] passwordb = new byte[password.length * 2];
					for (int i = 0; i < password.length; i++) {
						passwordb[i * 2] = (byte) (password[i] & 0xFF);
						passwordb[i * 2 + 1] = (byte) ((password[i] >> 8 & 0xFFFF) & 0xFF);
					}

					byte[] res=SCrypt.generate(passwordb, salt, scryptN, 8, 1, hashLength);
					Arrays.fill(passwordb, (byte)0);
					return res;
			}
		}
		catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException e) {
			throw new MessageExternalizationException(Integrity.FAIL, e);
		}
		throw new InternalError();
	}

	private byte[] uniformizeSaltLength(byte[] salt, int salt_length) {
		if (salt.length != salt_length) {
			if (salt.length < salt_length) {
				byte[] res = new byte[salt_length];
				System.arraycopy(salt, 0, res, 0, salt.length);
				for (int i = salt.length; i < res.length; i++)
					res[i] = 0;
				return res;
			} else {
				int size2 = salt.length / 2;
				byte[] res = new byte[Math.max(salt_length, size2)];
				for (int i = 0; i < size2; i++) {
					res[i] = salt[i * 2];
				}
				for (int i = size2; i < res.length; i++) {
					res[i] = salt[(i - size2) * 2 + 1];
				}
				return uniformizeSaltLength(res, salt_length);
			}
		}
		return salt;
	}

	public static PasswordHashType valueOf(HashedPassword identifiedHash)
	{
		byte[] t=identifiedHash.getBytes();
		if (t.length<2)
			throw new IllegalArgumentException();
		byte id=t[0];
		for (PasswordHashType p : PasswordHashType.values())
		{
			if (p.getID()==id)
				return p;
		}
		return null;
	}
	
	public static byte getCost(HashedPassword identifiedHash)
	{
		byte[] t=identifiedHash.getBytes();
		if (t.length<2)
			throw new IllegalArgumentException();
		return t[1];
	}
	
	public static byte getPasswordHashLengthBytes(HashedPassword identifiedHash)
	{
		short size=Bits.getShort(identifiedHash.getBytes(), 2);
		
		if (size>Byte.MAX_VALUE)
			throw new IllegalArgumentException();
		return (byte)size;
	}
	
	public static byte getSaltSizeBytes(HashedPassword identifiedHash)
	{
		byte[] t=identifiedHash.getBytes();
		int size=Bits.getShort(t, 2);
		size=t.length-2 - ObjectSizer.SHORT_FIELD_SIZE - size;
		
		if (size>Byte.MAX_VALUE)
			throw new IllegalArgumentException();
		return (byte)size;
	}
}

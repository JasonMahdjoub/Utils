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

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import org.bouncycastle.crypto.PasswordBasedDeriver;
import org.bouncycastle.crypto.PasswordConverter;
import org.bouncycastle.crypto.fips.FipsDigestAlgorithm;
import org.bouncycastle.crypto.fips.FipsPBKD;
import org.bouncycastle.crypto.fips.FipsSHS;
import org.bouncycastle.crypto.generators.BCrypt;
import org.bouncycastle.crypto.generators.SCrypt;

import com.distrimind.util.Bits;
import com.distrimind.util.OSValidator;
import com.distrimind.util.sizeof.ObjectSizer;


/**
 * 
 * @author Jason Mahdjoub
 * @version 2.2
 * @since Utils 1.8
 *
 */
public enum PasswordHashType {
	PBKDF2WithHmacSHA1("PBKDF2WithHmacSHA1", (byte) 32, CodeProvider.SunJCE, (byte)1),
	PBKDF2WithHMacSHA256("PBKDF2WithHMacSHA256", (byte) 32, CodeProvider.SunJCE, (byte)2),
	PBKDF2WithHMacSHA384("PBKDF2WithHMacSHA384", (byte) 32, CodeProvider.SunJCE, (byte)3),
	PBKDF2WithHMacSHA512("PBKDF2WithHMacSHA512", (byte) 32, CodeProvider.SunJCE, (byte)4),
	BCRYPT("BCRYPT", (byte) 24, CodeProvider.SUN, (byte)5), 
	SCRYPT_FOR_LOGIN("SCRYPT", (byte)32, CodeProvider.BC, (byte)6),
	SCRYPT_FOR_DATAENCRYPTION("SCRYPT", (byte)32, CodeProvider.BC, (byte)7),
	GNU_PBKDF2WithHmacSHA1("PBKDF2WithHMacSHA1", (byte) 32, CodeProvider.GNU_CRYPTO, (byte)8), 
	GNU_PBKDF2WithHMacSHA256("PBKDF2WithHMacSHA256",(byte) 32, CodeProvider.GNU_CRYPTO, (byte)9), 
	GNU_PBKDF2WithHMacSHA384("PBKDF2WithHMacSHA384", (byte) 32, CodeProvider.GNU_CRYPTO, (byte)10), 
	GNU_PBKDF2WithHMacSHA512("PBKDF2WithHMacSHA512", (byte) 32, CodeProvider.GNU_CRYPTO, (byte)11), 
	GNU_PBKDF2WithHMacWhirlpool("PBKDF2WithHMacWhirlpool",(byte) 32, CodeProvider.GNU_CRYPTO, (byte)12),
	BC_FIPS_PBKFD2WithHMacSHA2_256("PBKDF2WithHMacSHA256",(byte) 32, CodeProvider.BCFIPS, FipsSHS.Algorithm.SHA256_HMAC, (byte)13),
	BC_FIPS_PBKFD2WithHMacSHA2_384("PBKDF2WithHMacSHA384",(byte) 32, CodeProvider.BCFIPS, FipsSHS.Algorithm.SHA384_HMAC, (byte)14),
	BC_FIPS_PBKFD2WithHMacSHA2_512("PBKDF2WithHMacSHA512",(byte) 32, CodeProvider.BCFIPS, FipsSHS.Algorithm.SHA512_HMAC, (byte)15),
	DEFAULT(BCRYPT);

	
		
	
	private final byte hashLength;

	private PasswordHashType defaultOf;

	private final String algorithmName;
	
	private final CodeProvider codeProvider;
	
	private final FipsDigestAlgorithm fipsDigestAlgorithm;
	
	private final byte id;

	private PasswordHashType(PasswordHashType type) {
		this(type.algorithmName, type.hashLength, type.codeProvider, type.fipsDigestAlgorithm, type.id);
		this.defaultOf = type;
	}

	private PasswordHashType(String algorithmName, byte hashLength, CodeProvider codeProvider, FipsDigestAlgorithm fipsDigestAlgorithm, byte id) {
		this.hashLength = hashLength;
		this.defaultOf = null;
		this.algorithmName = algorithmName;
		this.codeProvider=codeProvider;
		this.fipsDigestAlgorithm=fipsDigestAlgorithm;
		this.id=id;
	}
	private PasswordHashType(String algorithmName, byte hashLength, CodeProvider codeProvider, byte id) {
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

	byte[] hash(byte data[], int off, int len, byte salt[], byte cost, byte hashLength)
			throws gnu.vm.jgnu.security.NoSuchAlgorithmException, gnu.vm.jgnu.security.spec.InvalidKeySpecException, gnu.vm.jgnu.security.NoSuchProviderException {
		if (cost<4 || cost>31)
			throw new IllegalArgumentException("cost must be greater or equals than 4 and lower or equals than 31");

		if (defaultOf != null)
			return defaultOf.hash(data, off, len, salt, cost, hashLength);
		
		if (OSValidator.getCurrentOS()==OSValidator.MACOS)
		{
			if (this==PBKDF2WithHMacSHA256)
				return PasswordHashType.BC_FIPS_PBKFD2WithHMacSHA2_256.hash(data, off, len, salt, cost, hashLength);
			if (this==PBKDF2WithHMacSHA384)
				return PasswordHashType.BC_FIPS_PBKFD2WithHMacSHA2_384.hash(data, off, len, salt, cost, hashLength);
			if (this==PBKDF2WithHMacSHA512)
				return PasswordHashType.BC_FIPS_PBKFD2WithHMacSHA2_512.hash(data, off, len, salt, cost, hashLength);
		}
		int scryptN=1<<18;
		int iterations=1<<(cost-1);
		switch (this) {
		case DEFAULT:
		case PBKDF2WithHmacSHA1: 
		case PBKDF2WithHMacSHA256:
		case PBKDF2WithHMacSHA384:
		case PBKDF2WithHMacSHA512:{
			try {
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
			} catch (NoSuchAlgorithmException e) {
				throw new gnu.vm.jgnu.security.NoSuchAlgorithmException(e);
			} catch (InvalidKeySpecException e) {
				throw new gnu.vm.jgnu.security.spec.InvalidKeySpecException(e);
			}
			catch(NoSuchProviderException e)
			{
				throw new gnu.vm.jgnu.security.NoSuchProviderException(e.getMessage());
			}
		}
		case GNU_PBKDF2WithHMacSHA256:
		case GNU_PBKDF2WithHMacSHA384:
		case GNU_PBKDF2WithHMacSHA512:
		case GNU_PBKDF2WithHMacWhirlpool:
		case GNU_PBKDF2WithHmacSHA1: {
			int size = len / 2;
			char[] password = new char[size + len % 2];
			for (int i = 0; i < size; i++) {
				password[i] = (char) ((data[off + i * 2] & 0xFF) & ((data[off + i * 2 + 1] << 8) & 0xFF));
			}
			if (size < password.length)
				password[size] = (char) (data[off + size * 2] & 0xFF);

			gnu.vm.jgnux.crypto.spec.PBEKeySpec spec = new gnu.vm.jgnux.crypto.spec.PBEKeySpec(password, salt,
					iterations, (hashLength) );
			gnu.vm.jgnux.crypto.SecretKeyFactory skf = gnu.vm.jgnux.crypto.SecretKeyFactory.getInstance(algorithmName);
			return skf.generateSecret(spec).getEncoded();
		}
		case BCRYPT: {
			byte[] passwordb = null;
			if (off != 0 || len != data.length) {
				passwordb = new byte[len];
				System.arraycopy(data, off, passwordb, 0, len);
			} else
				passwordb = data;

			salt = uniformizeSaltLength(salt, 16);
			
			return BCrypt.generate(passwordb, salt, cost);
		}
		case BC_FIPS_PBKFD2WithHMacSHA2_256:
		case BC_FIPS_PBKFD2WithHMacSHA2_384:
		case BC_FIPS_PBKFD2WithHMacSHA2_512:
		{
			CodeProvider.ensureBouncyCastleProviderLoaded();
			PasswordBasedDeriver<org.bouncycastle.crypto.fips.FipsPBKD.Parameters> deriver = 
						new FipsPBKD.DeriverFactory().createDeriver(FipsPBKD.PBKDF2.using(fipsDigestAlgorithm, data)
												.withIterationCount(iterations)
												.withSalt(salt));
			return deriver.deriveKey(PasswordBasedDeriver.KeyType.CIPHER,((hashLength*8) +7) / 8);
		}
		case SCRYPT_FOR_LOGIN:
			
			scryptN=1<<13;
			
		case SCRYPT_FOR_DATAENCRYPTION:
		{
			byte []d=null;
			if (len==data.length && off==0)
				d=data;
			else
			{
				d=new byte[len];
				System.arraycopy(data, off, d, 0, len);
			}
			return SCrypt.generate(d, salt, scryptN, 8, 1, hashLength);
		}	
		default:
			break;
			
			

		}
		return null;
	}

	byte[] hash(char password[], byte salt[], byte cost, byte hashLength)
			throws gnu.vm.jgnu.security.NoSuchAlgorithmException, gnu.vm.jgnu.security.spec.InvalidKeySpecException, gnu.vm.jgnu.security.NoSuchProviderException {
		if (cost<4 || cost>31)
			throw new IllegalArgumentException("cost must be greater or equals than 4 and lower or equals than 31");

		if (defaultOf != null)
			return defaultOf.hash(password, salt, cost, hashLength);
		if (OSValidator.getCurrentOS()==OSValidator.MACOS)
		{
			if (this==PBKDF2WithHMacSHA256)
				return PasswordHashType.BC_FIPS_PBKFD2WithHMacSHA2_256.hash(password, salt, cost, hashLength);
			if (this==PBKDF2WithHMacSHA384)
				return PasswordHashType.BC_FIPS_PBKFD2WithHMacSHA2_384.hash(password, salt, cost, hashLength);
			if (this==PBKDF2WithHMacSHA512)
				return PasswordHashType.BC_FIPS_PBKFD2WithHMacSHA2_512.hash(password, salt, cost, hashLength);
		}
		int iterations=1<<(cost-1);
		int scryptN=1<<18;
		switch (this) {
		case DEFAULT:
		case PBKDF2WithHmacSHA1:
		case PBKDF2WithHMacSHA256:
		case PBKDF2WithHMacSHA384:
		case PBKDF2WithHMacSHA512:{
			try {
				PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, (hashLength) * 8);
				SecretKeyFactory skf = SecretKeyFactory.getInstance(algorithmName, codeProvider.checkProviderWithCurrentOS().name());
				return skf.generateSecret(spec).getEncoded();
			} catch (NoSuchAlgorithmException e) {
				throw new gnu.vm.jgnu.security.NoSuchAlgorithmException(e);
			} catch (InvalidKeySpecException e) {
				throw new gnu.vm.jgnu.security.spec.InvalidKeySpecException(e);
			}
			catch(NoSuchProviderException e)
			{
				throw new gnu.vm.jgnu.security.NoSuchProviderException(e.getMessage());
			}
		}
		case GNU_PBKDF2WithHMacSHA256:
		case GNU_PBKDF2WithHMacSHA384:
		case GNU_PBKDF2WithHMacSHA512:
		case GNU_PBKDF2WithHMacWhirlpool:
		case GNU_PBKDF2WithHmacSHA1: {
			gnu.vm.jgnux.crypto.spec.PBEKeySpec spec = new gnu.vm.jgnux.crypto.spec.PBEKeySpec(password, salt,
					iterations, (hashLength) );
			gnu.vm.jgnux.crypto.SecretKeyFactory skf = gnu.vm.jgnux.crypto.SecretKeyFactory.getInstance(algorithmName);
			return skf.generateSecret(spec).getEncoded();
		}
		case BCRYPT: {
			
			salt = uniformizeSaltLength(salt, 16);
			return BCrypt.generate(BCrypt.passwordToByteArray(password), salt, cost);
		}
		case BC_FIPS_PBKFD2WithHMacSHA2_256:
		case BC_FIPS_PBKFD2WithHMacSHA2_384:
		case BC_FIPS_PBKFD2WithHMacSHA2_512:
		{
			CodeProvider.ensureBouncyCastleProviderLoaded();
			PasswordBasedDeriver<org.bouncycastle.crypto.fips.FipsPBKD.Parameters> deriver = 
						new FipsPBKD.DeriverFactory().createDeriver(FipsPBKD.PBKDF2.using(fipsDigestAlgorithm, PasswordConverter.UTF8.convert(password))
												.withIterationCount(iterations)
												.withSalt(salt));
			return deriver.deriveKey(PasswordBasedDeriver.KeyType.CIPHER,((hashLength*8) +7) / 8);
		}
		case SCRYPT_FOR_LOGIN:
			scryptN=1<<13;
			
		case SCRYPT_FOR_DATAENCRYPTION:
			byte[] passwordb = new byte[password.length * 2];
			for (int i = 0; i < password.length; i++) {
				passwordb[i * 2] = (byte) (password[i] & 0xFF);
				passwordb[i * 2 + 1] = (byte) ((password[i] >> 8 & 0xFFFF) & 0xFF);
			}
			
			return SCrypt.generate(passwordb, salt, scryptN, 8, 1, hashLength);
		}
		return null;
	}

	private byte[] uniformizeSaltLength(byte salt[], int salt_length) {
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

	public static PasswordHashType valueOf(byte identifiedHash[])
	{
		if (identifiedHash.length<2)
			throw new IllegalArgumentException();
		byte id=identifiedHash[0];
		for (PasswordHashType p : PasswordHashType.values())
		{
			if (p.getID()==id)
				return p;
		}
		return null;
	}
	
	public static byte getCost(byte identifiedHash[])
	{
		if (identifiedHash.length<2)
			throw new IllegalArgumentException();
		return identifiedHash[1];
	}
	
	public static byte getPasswordHashLengthBytes(byte identifiedHash[])
	{
		short size=Bits.getShort(identifiedHash, 2);
		
		if (size>Byte.MAX_VALUE)
			throw new IllegalArgumentException();
		return (byte)size;
	}
	
	public static byte getSaltSizeBytes(byte identifiedHash[])
	{
		int size=Bits.getShort(identifiedHash, 2);
		size=identifiedHash.length-2 - ObjectSizer.SHORT_FIELD_SIZE - size;
		
		if (size>Byte.MAX_VALUE)
			throw new IllegalArgumentException();
		return (byte)size;
	}
}

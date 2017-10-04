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

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import com.berry.BCrypt;

/**
 * 
 * @author Jason Mahdjoub
 * @version 2.0
 * @since Utils 1.8
 *
 */
public enum PasswordHashType {
	PBKDF2WithHmacSHA1("PBKDF2WithHmacSHA1", (byte) 32, CodeProvider.SUN), 
	BCRYPT("BCRYPT", (byte) 32, CodeProvider.SUN), 
	GNU_PBKDF2WithHmacSHA1("PBKDF2WithHMacSHA1", (byte) 32, CodeProvider.GNU_CRYPTO), 
	GNU_PBKDF2WithHMacSHA256("PBKDF2WithHMacSHA256",(byte) 32, CodeProvider.GNU_CRYPTO), 
	GNU_PBKDF2WithHMacSHA384("PBKDF2WithHMacSHA384", (byte) 32, CodeProvider.GNU_CRYPTO), 
	GNU_PBKDF2WithHMacSHA512("PBKDF2WithHMacSHA512", (byte) 32, CodeProvider.GNU_CRYPTO), 
	GNU_PBKDF2WithHMacWhirlpool("PBKDF2WithHMacWhirlpool",(byte) 32, CodeProvider.GNU_CRYPTO),
	BC_FIPS_PBKFD2WithHMacSHA256("HmacSHA256",(byte) 32, CodeProvider.BCFIPS),
	BC_FIPS_PBKFD2WithHMacSHA384("HmacSHA384",(byte) 32, CodeProvider.BCFIPS),
	BC_FIPS_PBKFD2WithHMacSHA512("HmacSHA512",(byte) 32, CodeProvider.BCFIPS),
	DEFAULT(BCRYPT);

	private final byte hashLength;

	private PasswordHashType defaultOf;

	private final String algorithmName;
	
	private final CodeProvider codeProvider;

	private PasswordHashType(PasswordHashType type) {
		this(type.algorithmName, type.hashLength, type.codeProvider);
		this.defaultOf = type;
	}

	private PasswordHashType(String algorithmName, byte hashLength, CodeProvider codeProvider) {
		this.hashLength = hashLength;
		this.defaultOf = null;
		this.algorithmName = algorithmName;
		this.codeProvider=codeProvider;
	}
	
	public CodeProvider getCodeProvider()
	{
		return codeProvider;
	}
	public byte getDefaultHashLengthBytes()
	{
		return hashLength;
	}

	byte[] hash(byte data[], int off, int len, byte salt[], int iterations, byte hashLength)
			throws gnu.vm.jgnu.security.NoSuchAlgorithmException, gnu.vm.jgnu.security.spec.InvalidKeySpecException, gnu.vm.jgnu.security.NoSuchProviderException {
		if (defaultOf != null)
			return defaultOf.hash(data, off, len, salt, iterations, hashLength);
		switch (this) {
		case DEFAULT:
		case PBKDF2WithHmacSHA1: {
			try {
				int size = len / 2;
				char[] password = new char[size + len % 2];
				for (int i = 0; i < size; i++) {
					password[i] = (char) ((data[off + i * 2] & 0xFF) & ((data[off + i * 2 + 1] << 8) & 0xFF));
				}
				if (size < password.length)
					password[size] = (char) (data[off + size * 2] & 0xFF);

				PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, (hashLength) * 8);
				SecretKeyFactory skf = SecretKeyFactory.getInstance(algorithmName);
				return skf.generateSecret(spec).getEncoded();
			} catch (NoSuchAlgorithmException e) {
				throw new gnu.vm.jgnu.security.NoSuchAlgorithmException(e);
			} catch (InvalidKeySpecException e) {
				throw new gnu.vm.jgnu.security.spec.InvalidKeySpecException(e);
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
					iterations, (hashLength) * 8);
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

			BCrypt B = new BCrypt();
			salt = uniformizeSaltLength(salt, BCrypt.BCRYPT_SALT_LEN);
			return B.crypt_raw(passwordb, salt, (int) Math.log(iterations), BCrypt.bf_crypt_ciphertext.clone());
		}
		case BC_FIPS_PBKFD2WithHMacSHA256:
		case BC_FIPS_PBKFD2WithHMacSHA384:
		case BC_FIPS_PBKFD2WithHMacSHA512:
		{
			CodeProvider.ensureBouncyCastleProviderLoaded();
			try
			{
				int size = len / 2;
				char[] password = new char[size + len % 2];
				for (int i = 0; i < size; i++) {
					password[i] = (char) ((data[off + i * 2] & 0xFF) & ((data[off + i * 2 + 1] << 8) & 0xFF));
				}
				if (size < password.length)
					password[size] = (char) (data[off + size * 2] & 0xFF);
	
				SecretKeyFactory keyFact = SecretKeyFactory.getInstance(algorithmName,codeProvider.name());
				
				SecretKey hmacKey = keyFact.generateSecret(new PBEKeySpec(password,  salt,iterations,hashLength*8));
				
				return hmacKey.getEncoded();
			}
			catch(NoSuchProviderException e)
			{
				throw new gnu.vm.jgnu.security.NoSuchProviderException(e.getMessage());
			}
			catch(NoSuchAlgorithmException e)
			{
				throw new gnu.vm.jgnu.security.NoSuchAlgorithmException(e);
			} catch (InvalidKeySpecException e) {
				throw new gnu.vm.jgnu.security.spec.InvalidKeySpecException(e);
			}
		}
			
			

		}
		return null;
	}

	byte[] hash(char password[], byte salt[], int iterations, byte hashLength)
			throws gnu.vm.jgnu.security.NoSuchAlgorithmException, gnu.vm.jgnu.security.spec.InvalidKeySpecException, gnu.vm.jgnu.security.NoSuchProviderException {
		if (defaultOf != null)
			return defaultOf.hash(password, salt, iterations, hashLength);
		switch (this) {
		case DEFAULT:
		case PBKDF2WithHmacSHA1: {
			try {
				PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, (hashLength) * 8);
				SecretKeyFactory skf = SecretKeyFactory.getInstance(algorithmName);
				return skf.generateSecret(spec).getEncoded();
			} catch (NoSuchAlgorithmException e) {
				throw new gnu.vm.jgnu.security.NoSuchAlgorithmException(e);
			} catch (InvalidKeySpecException e) {
				throw new gnu.vm.jgnu.security.spec.InvalidKeySpecException(e);
			}

		}
		case GNU_PBKDF2WithHMacSHA256:
		case GNU_PBKDF2WithHMacSHA384:
		case GNU_PBKDF2WithHMacSHA512:
		case GNU_PBKDF2WithHMacWhirlpool:
		case GNU_PBKDF2WithHmacSHA1: {
			gnu.vm.jgnux.crypto.spec.PBEKeySpec spec = new gnu.vm.jgnux.crypto.spec.PBEKeySpec(password, salt,
					iterations, (hashLength) * 8);
			gnu.vm.jgnux.crypto.SecretKeyFactory skf = gnu.vm.jgnux.crypto.SecretKeyFactory.getInstance(algorithmName);
			return skf.generateSecret(spec).getEncoded();
		}
		case BCRYPT: {
			byte[] passwordb = new byte[password.length * 2];
			for (int i = 0; i < password.length; i++) {
				passwordb[i * 2] = (byte) (password[i] & 0xFF);
				passwordb[i * 2 + 1] = (byte) ((password[i] >> 8 & 0xFFFF) & 0xFF);
			}
			BCrypt B = new BCrypt();
			salt = uniformizeSaltLength(salt, BCrypt.BCRYPT_SALT_LEN);
			return B.crypt_raw(passwordb, salt, (int) Math.log(iterations), BCrypt.bf_crypt_ciphertext.clone());
		}
		case BC_FIPS_PBKFD2WithHMacSHA256:
		case BC_FIPS_PBKFD2WithHMacSHA384:
		case BC_FIPS_PBKFD2WithHMacSHA512:
		{
			try
			{
				CodeProvider.ensureBouncyCastleProviderLoaded();
				SecretKeyFactory keyFact = SecretKeyFactory.getInstance(algorithmName,CodeProvider.BCFIPS.name());
				
				SecretKey hmacKey = keyFact.generateSecret(new PBEKeySpec(password,  salt,iterations,hashLength*8));
				
				return hmacKey.getEncoded();
			}
			catch(NoSuchProviderException e)
			{
				throw new gnu.vm.jgnu.security.NoSuchProviderException(e.getMessage());
			}
			catch(NoSuchAlgorithmException e)
			{
				throw new gnu.vm.jgnu.security.NoSuchAlgorithmException(e);
			} catch (InvalidKeySpecException e) {
				throw new gnu.vm.jgnu.security.spec.InvalidKeySpecException(e);
			}
		}
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

}

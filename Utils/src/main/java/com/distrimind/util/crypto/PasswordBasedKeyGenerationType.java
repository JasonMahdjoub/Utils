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

import javax.crypto.spec.SecretKeySpec;

import gnu.vm.jgnu.security.NoSuchAlgorithmException;
import gnu.vm.jgnu.security.NoSuchProviderException;
import gnu.vm.jgnu.security.spec.InvalidKeySpecException;

/**
 * 
 * @author Jason Mahdjoub
 * @version 1.1
 * @since Utils 1.17.0
 */
public enum PasswordBasedKeyGenerationType {
	PBKDF2WithHmacSHA1(PasswordHashType.PBKDF2WithHmacSHA1), 
	GNU_PBKDF2WithHmacSHA1(PasswordHashType.GNU_PBKDF2WithHmacSHA1), 
	GNU_PBKDF2WithHMacSHA256(PasswordHashType.GNU_PBKDF2WithHMacSHA256), 
	GNU_PBKDF2WithHMacSHA384(PasswordHashType.GNU_PBKDF2WithHMacSHA384), 
	GNU_PBKDF2WithHMacSHA512(PasswordHashType.GNU_PBKDF2WithHMacSHA512), 
	GNU_PBKDF2WithHMacWhirlpool(PasswordHashType.GNU_PBKDF2WithHMacWhirlpool),
	BC_FIPS_PBKFD2WithHMacSHA256(PasswordHashType.BC_FIPS_PBKFD2WithHMacSHA256),
	BC_FIPS_PBKFD2WithHMacSHA384(PasswordHashType.BC_FIPS_PBKFD2WithHMacSHA384),
	BC_FIPS_PBKFD2WithHMacSHA512(PasswordHashType.BC_FIPS_PBKFD2WithHMacSHA512),
	SCRYPT_FOR_LOGIN(PasswordHashType.SCRYPT_FOR_LOGIN),
	SCRYPT_FOR_DATAENCRYPTION(PasswordHashType.SCRYPT_FOR_LOGIN),
	DEFAULT(BC_FIPS_PBKFD2WithHMacSHA384);
	
	
	private final PasswordHashType passwordHashType;
	private PasswordBasedKeyGenerationType(PasswordHashType passwordHashType)
	{
		this.passwordHashType=passwordHashType;
	}
	private PasswordBasedKeyGenerationType(PasswordBasedKeyGenerationType other)
	{
		this(other.passwordHashType);
	}
	public SymmetricSecretKey derivateKey(char[] password, byte[] salt, SymmetricEncryptionType type) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException
	{
		return derivateKey(password, salt, PasswordHash.DEFAULT_NB_ITERATIONS, type, type.getDefaultKeySizeBits());
	}
	public SymmetricSecretKey derivateKey(char[] password, byte[] salt, int iterationNumber, SymmetricEncryptionType type) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException
	{
		return derivateKey(password, salt, iterationNumber, type, type.getDefaultKeySizeBits());
	}
	public SymmetricSecretKey derivateKey(char[] password, byte[] salt, int iterationNumber, SymmetricEncryptionType type, short keySizeBits) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException
	{
		if (getCodeProvider()==CodeProvider.GNU_CRYPTO)
		{
			return new SymmetricSecretKey(type, new gnu.vm.jgnux.crypto.spec.SecretKeySpec(passwordHashType.hash(password, salt, iterationNumber, (byte)(keySizeBits/8)), type.getAlgorithmName()), keySizeBits);
		}
		else
		{
			return new SymmetricSecretKey(type, new SecretKeySpec(passwordHashType.hash(password, salt, iterationNumber, (byte)(keySizeBits/8)), type.getAlgorithmName()), keySizeBits);
		}
	}
	public SymmetricSecretKey derivateKey(char[] password, byte[] salt, int iterationNumber, SymmetricAuthentifiedSignatureType type) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException
	{
		return derivateKey(password, salt, iterationNumber, type, type.getDefaultKeySizeBits());
	}
	public SymmetricSecretKey derivateKey(char[] password, byte[] salt, SymmetricAuthentifiedSignatureType type) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException
	{
		return derivateKey(password, salt, PasswordHash.DEFAULT_NB_ITERATIONS, type, type.getDefaultKeySizeBits());
	}
	
	public SymmetricSecretKey derivateKey(char[] password, byte[] salt, int iterationNumber, SymmetricAuthentifiedSignatureType type, short keySizeBits) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException
	{
		return new SymmetricSecretKey(type, new SecretKeySpec(passwordHashType.hash(password, salt, iterationNumber, (byte)(keySizeBits/8)), type.getAlgorithmName()), keySizeBits);
	}
	
	public CodeProvider getCodeProvider()
	{
		return passwordHashType.getCodeProvider();
	}
}

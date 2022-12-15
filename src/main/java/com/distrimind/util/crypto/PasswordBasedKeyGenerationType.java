/*
Copyright or © or Corp. Jason Mahdjoub (04/02/2016)

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
import java.io.IOException;

/**
 * 
 * @author Jason Mahdjoub
 * @version 1.1
 * @since Utils 1.17.0
 */
public enum PasswordBasedKeyGenerationType {
	PBKDF2WithHmacSHA1(PasswordHashType.PBKDF2WithHmacSHA1),
	@Deprecated
	GNU_PBKDF2WithHmacSHA1(PasswordHashType.GNU_PBKDF2WithHmacSHA1),
	@Deprecated
	GNU_PBKDF2WithHMacSHA256(PasswordHashType.GNU_PBKDF2WithHMacSHA2_256),
	@Deprecated
	GNU_PBKDF2WithHMacSHA384(PasswordHashType.GNU_PBKDF2WithHMacSHA2_384),
	@Deprecated
	GNU_PBKDF2WithHMacSHA512(PasswordHashType.GNU_PBKDF2WithHMacSHA2_512),
	@Deprecated
	GNU_PBKDF2WithHMacWhirlpool(PasswordHashType.GNU_PBKDF2WithHMacWhirlpool),
	BC_FIPS_PBKFD2WithHMacSHA2_256(PasswordHashType.BC_FIPS_PBKFD2WithHMacSHA2_256),
	BC_FIPS_PBKFD2WithHMacSHA2_384(PasswordHashType.BC_FIPS_PBKFD2WithHMacSHA2_384),
	BC_FIPS_PBKFD2WithHMacSHA2_512(PasswordHashType.BC_FIPS_PBKFD2WithHMacSHA2_512),
	BC_SCRYPT_FOR_LOGIN(PasswordHashType.BC_SCRYPT_FOR_LOGIN),
	BC_SCRYPT_FOR_DATA_ENCRYPTION(PasswordHashType.BC_SCRYPT_FOR_LOGIN),
	DEFAULT(BC_FIPS_PBKFD2WithHMacSHA2_384);
	
	
	private final PasswordHashType passwordHashType;

	public boolean equals(PasswordBasedKeyGenerationType type)
	{
		if (type==null)
			return false;
		return type.passwordHashType.equals(this.passwordHashType);
	}

	PasswordBasedKeyGenerationType(PasswordHashType passwordHashType)
	{
		this.passwordHashType=passwordHashType;
	}
	PasswordBasedKeyGenerationType(PasswordBasedKeyGenerationType other)
	{
		this(other.passwordHashType);
	}
	public SymmetricSecretKey derivativeKey(char[] password, byte[] salt, SymmetricEncryptionType type) throws IOException
	{
		return derivativeKey(password, salt, PasswordHash.DEFAULT_COST, type, type.getDefaultKeySizeBits());
	}
	public SymmetricSecretKey derivativeKey(char[] password, byte[] salt, byte cost, SymmetricEncryptionType type) throws IOException
	{
		return derivativeKey(password, salt, cost, type, type.getDefaultKeySizeBits());
	}
	public SymmetricSecretKey derivativeKey(char[] password, byte[] salt, byte cost, SymmetricEncryptionType type, short keySizeBits) throws IOException {
		if (cost<4 || cost>31)
			throw new IllegalArgumentException("cost must be greater or equals than 4 and lower or equals than 31");
		if (getCodeProvider()==CodeProvider.GNU_CRYPTO)
		{
			return new SymmetricSecretKey(type, GnuFunctions.secretKeySpecGetInstance(passwordHashType.hash(password, salt, cost, (byte)(keySizeBits/8)), type.getAlgorithmName()), keySizeBits);
		}
		else
		{
			return new SymmetricSecretKey(type, new SecretKeySpec(passwordHashType.hash(password, salt, cost, (byte)(keySizeBits/8)), type.getAlgorithmName()), keySizeBits);
		}
	}
	public SymmetricSecretKey derivativeKey(char[] password, byte[] salt, byte cost, SymmetricAuthenticatedSignatureType type) throws IOException
	{
		return derivativeKey(password, salt, cost, type, type.getDefaultKeySizeBits());
	}
	public SymmetricSecretKey derivativeKey(char[] password, byte[] salt, SymmetricAuthenticatedSignatureType type) throws IOException
	{
		return derivativeKey(password, salt, PasswordHash.DEFAULT_COST, type, type.getDefaultKeySizeBits());
	}
	
	public SymmetricSecretKey derivativeKey(char[] password, byte[] salt, byte cost, SymmetricAuthenticatedSignatureType type, short keySizeBits) throws IOException {
		if (cost<4 || cost>31)
			throw new IllegalArgumentException("cost must be greater or equals than 4 and lower or equals than 31");
		return new SymmetricSecretKey(type, new SecretKeySpec(passwordHashType.hash(password, salt, cost, (byte)(keySizeBits/8)), type.getAlgorithmName()), keySizeBits);
	}
	
	public CodeProvider getCodeProvider()
	{
		return passwordHashType.getCodeProvider();
	}
}

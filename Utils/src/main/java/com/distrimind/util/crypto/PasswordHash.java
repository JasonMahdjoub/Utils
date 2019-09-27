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
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

import com.distrimind.util.Bits;
import com.distrimind.util.sizeof.ObjectSizer;


/**
 * 
 * @author Jason Mahdjoub
 * @version 3.0
 * @since Utils 1.8
 *
 */
public class PasswordHash {
	final static byte DEFAULT_SALT_SIZE = 24;

	final static byte DEFAULT_COST = 16;

	public static byte[] generateSalt(SecureRandom random, int saltSize) {
		byte[] res = new byte[saltSize];
		random.nextBytes(res);
		return res;
	}

	private final PasswordHashType type;

	private final SecureRandom random;

	private byte saltSize;

	private byte cost;
	

	public PasswordHash() {
		this(PasswordHashType.DEFAULT);
	}

	public PasswordHash(PasswordHashType type) {
		this(type, new SecureRandom());
	}
	

	public PasswordHash(PasswordHashType type, SecureRandom random) {
		this(type, random, DEFAULT_COST, DEFAULT_SALT_SIZE);
	}
	public PasswordHash(PasswordHashType type, SecureRandom random, byte cost) {
		this(type, random, cost, DEFAULT_SALT_SIZE);
	}
	public PasswordHash(PasswordHashType type, SecureRandom random, byte cost, byte saltSize) {
		if (cost<4 || cost>31)
			throw new IllegalArgumentException("cost must be greater or equals than 4 and lower or equals than 31");

		this.type = type;
		this.random = random;
		this.cost = cost;
		this.saltSize = saltSize;
	}


	public static boolean checkValidHashedPassword(char[] password, byte[] goodHash) {
		return checkValidHashedPassword(password, goodHash, null);
	}

	public static boolean checkValidHashedPassword(char[] password, byte[] goodHash, byte[] staticAdditionalSalt) {
		PasswordHashType type=PasswordHashType.valueOf(goodHash);
		byte cost=PasswordHashType.getCost(goodHash);
		try {
			
			
			//byte []composedHash=getHashFromIdentifiedHash(goodHash);
			byte[][] separated = Bits.separateEncodingsWithShortSizedTabs(goodHash, 2, goodHash.length-2);
			byte[] generatedSalt = separated[1];
			byte[] salt = mixSaltWithStaticSalt(generatedSalt, staticAdditionalSalt);
			byte[] hash = separated[0];

			assert type != null;
			return Arrays.equals(type.hash(password, salt, cost, (byte)hash.length), hash);
		} catch (Exception e) {
			return false;
		}
	}

	public static boolean checkValidHashedPassword(String password, byte[] goodHash) {
		return checkValidHashedPassword(password.toCharArray(), goodHash);
	}
	public static boolean checkValidHashedPassword(String password, byte[] goodHash, byte[] staticAdditionalSalt) {
		return checkValidHashedPassword(password.toCharArray(), goodHash, staticAdditionalSalt);
	}

	public byte getCost() {
		return cost;
	}

	public byte getSaltSizeBytes() {
		return saltSize;
	}

	public byte[] hash(char[] password)
			throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
		return hash(password, null, type.getDefaultHashLengthBytes());
	}
	public byte[] hash(char[] password, byte defaultHashLengthBytes)
			throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
		return hash(password, null, defaultHashLengthBytes);
	}
	public byte[] hash(char[] password, byte[] staticAdditionalSalt) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException
	{
		return hash(password, staticAdditionalSalt, type.getDefaultHashLengthBytes());
	}
	public byte[] hash(char[] password, byte[] staticAdditionalSalt, byte hashLengthBytes)
			throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
		if (password == null)
			throw new NullPointerException("password");

		byte[] generatedSalt = generateSalt(random, saltSize);
		byte[] salt = mixSaltWithStaticSalt(generatedSalt, staticAdditionalSalt);
		return getIdentifiedHash(Bits.concatenateEncodingWithShortSizedTabs(type.hash(password, salt, cost, hashLengthBytes), generatedSalt));
		
	}
	
	private byte[] getIdentifiedHash(byte[] hash)
	{
		byte[] res = new byte[hash.length + 2];
		res[0]=type.getID();
		res[1]=cost;
		System.arraycopy(hash, 0, res, ObjectSizer.SHORT_FIELD_SIZE, hash.length);
		return res;
	}

	
	
	
	/*tatic byte[] getHashFromIdentifiedHash(byte identifiedHash[])
	{
		byte res[]=new byte[identifiedHash.length-2];
		System.arraycopy(identifiedHash, 2, res, 0, res.length);
		return res;
	}*/
	public byte[] hash(String password)
			throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
		return hash(password.toCharArray());
	}
	public byte[] hash(String password, byte defaultHashLengthBytes)
			throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
		return hash(password.toCharArray(), defaultHashLengthBytes);
	}
	public byte[] hash(String password, byte[] staticAdditionalSalt) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException
	{
		return hash(password, staticAdditionalSalt, type.getDefaultHashLengthBytes());
	}
	public byte[] hash(String password, byte[] staticAdditionalSalt, byte defaultHashLengthBytes)
			throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
		return hash(password.toCharArray(), staticAdditionalSalt, defaultHashLengthBytes);
	}

	private static byte[] mixSaltWithStaticSalt(byte[] salt, byte[] staticAdditionalSalt) {
		if (staticAdditionalSalt != null) {
			byte[] res = new byte[salt.length + staticAdditionalSalt.length];
			System.arraycopy(salt, 0, res, 0, salt.length);
			System.arraycopy(staticAdditionalSalt, 0, res, salt.length, staticAdditionalSalt.length);
			return res;
		}
		return salt;
	}

	public void setCost(byte cost) {
		if (cost<4 || cost>31)
			throw new IllegalArgumentException("cost must be greater or equals than 4 and lower or equals than 31");

		this.cost = cost;
	}

	public void setSaltSize(byte _saltSize) {
		saltSize = _saltSize;
	}

}

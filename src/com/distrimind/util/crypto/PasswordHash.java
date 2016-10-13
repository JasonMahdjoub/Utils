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
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

import com.distrimind.util.Bits;

/**
 * 
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 1.8
 *
 */
public class PasswordHash
{
    private final PasswordHashType type;
    private final SecureRandom random;
    final static int DEFAULT_SALT_SIZE=24;
    final static int DEFAULT_NB_ITERATIONS=100000;
    
    private int saltSize;
    
    int getSaltSize()
    {
        return saltSize;
    }

    void setSaltSize(int _saltSize)
    {
        saltSize = _saltSize;
    }

    int getHashIterationsNumber()
    {
        return hashIterationsNumber;
    }

    void setHashIterationsNumber(int _hashIterationsNumber)
    {
        hashIterationsNumber = _hashIterationsNumber;
    }



    private int hashIterationsNumber;
    
    public PasswordHash()
    {
	this(PasswordHashType.DEFAULT);
    }

    public PasswordHash(PasswordHashType type)
    {
	this(type, new SecureRandom());
    }
    public PasswordHash(PasswordHashType type, SecureRandom random)
    {
	this.type=type;
	this.random=random;
	this.saltSize=DEFAULT_SALT_SIZE;
	this.hashIterationsNumber=DEFAULT_NB_ITERATIONS;
    }
    
    public static byte[] generateSalt(SecureRandom random, int saltSize)
    {
	byte[] res=new byte[saltSize];
	random.nextBytes(res);
	return res;
    }
    
    public byte[] hash(String password) throws NoSuchAlgorithmException, InvalidKeySpecException
    {
	return hash(password.toCharArray());
    }

    public byte[] hash(String password, byte[] staticAdditionalSalt) throws NoSuchAlgorithmException, InvalidKeySpecException
    {
	return hash(password.toCharArray(), staticAdditionalSalt);
    }
    
    public byte[] hash(char[] password) throws NoSuchAlgorithmException, InvalidKeySpecException
    {
	return hash(password, null);
    }
    
    private byte[] mixSaltWithStaticSalt(byte[] salt, byte[] staticAdditionalSalt)
    {
	if (staticAdditionalSalt!=null)
	{
	    byte[] res=new byte[salt.length+staticAdditionalSalt.length];
	    System.arraycopy(salt, 0, res, 0, salt.length);
	    System.arraycopy(staticAdditionalSalt, 0, res, salt.length, staticAdditionalSalt.length);
	    return res;
	}
	return salt;
    }
    
    public byte[] hash(char[] password, byte[] staticAdditionalSalt) throws NoSuchAlgorithmException, InvalidKeySpecException
    {
	if (password==null)
	    throw new NullPointerException("password");
	
	byte[] generatedSalt=generateSalt(random, saltSize);
	byte[] salt=mixSaltWithStaticSalt(generatedSalt, staticAdditionalSalt);
	return Bits.concateEncodingWithShortSizedTabs(type.hash(password, salt, hashIterationsNumber), generatedSalt);
    }
    
    public boolean checkValidHashedPassword(char password[], byte[] goodHash, byte[] staticAdditionalSalt)
    {
	try
	{
	    byte[][] separated=Bits.separateEncodingsWithShortSizedTabs(goodHash);
	    byte[] generatedSalt=separated[1];
	    byte[] salt=mixSaltWithStaticSalt(generatedSalt, staticAdditionalSalt);
	
	    return Arrays.equals(type.hash(password, salt, hashIterationsNumber), separated[0]);
	}
	catch(Exception e)
	{
	    return false;
	}
    }
    public boolean checkValidHashedPassword(char password[], byte[] goodHash)
    {
	return this.checkValidHashedPassword(password, goodHash, null);
    }
    public boolean checkValidHashedPassword(String password, byte[] goodHash, byte[] staticAdditionalSalt)
    {
	return checkValidHashedPassword(password.toCharArray(), goodHash, staticAdditionalSalt);
    }
    public boolean checkValidHashedPassword(String password, byte[] goodHash)
    {
	return checkValidHashedPassword(password.toCharArray(), goodHash);
    }
    
}

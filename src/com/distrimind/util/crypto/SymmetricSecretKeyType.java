/*
 * Utils is created and developped by Jason MAHDJOUB (jason.mahdjoub@distri-mind.fr) at 2016.
 * Utils was developped by Jason Mahdjoub. 
 * Individual contributors are indicated by the @authors tag.
 * 
 * This file is part of Utils.
 * 
 * This is free software; you can redistribute it and/or modify it under the
 * terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation; either version 3.0 of the License.
 * 
 * This software is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
 * details.
 * 
 * You should have received a copy of the GNU Lesser General Public License
 * along with this software; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA, or see the FSF
 * site: http://www.fsf.org.
 */
package com.distrimind.util.crypto;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * 
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 1.4
 */
public enum SymmetricSecretKeyType
{
    DES("DES"),
    DESede("DESede");
    
    private final String algorithm;
    private final int keySize;
    private SymmetricSecretKeyType(String algorithm)
    {
	this.algorithm=algorithm;
	this.keySize=256;
    }
    
    
    public SecretKey getSecretKey(SymmetricEncryptionType encryption_type, String password, SecureRandom random) throws NoSuchAlgorithmException, InvalidKeySpecException
    {
	return getSecretKey(encryption_type, password.toCharArray(), random);
    }
    
    public SecretKey getSecretKey(SymmetricEncryptionType encryption_type, char password[], SecureRandom random) throws NoSuchAlgorithmException, InvalidKeySpecException
    {
	byte salt[]=new byte[20];
	random.nextBytes(salt);
	SecretKeyFactory factory = SecretKeyFactory.getInstance(algorithm);
	KeySpec spec = new PBEKeySpec(password, salt, 65536, keySize);
	SecretKey tmp = factory.generateSecret(spec);
	SecretKey secret = new SecretKeySpec(tmp.getEncoded(),encryption_type.getAlgorithmName());
	return secret;
    }
}

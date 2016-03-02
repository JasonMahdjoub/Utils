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
import java.security.Signature;

/**
 * List of signature algorithms
 * 
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 1.4
 */
public enum SignatureType
{
    SHA1withRSA("SHA1withRSA"),
    SHA256withRSA("SHA256withRSA"),
    SHA384withRSA("SHA384withRSA"),
    SHA512withRSA("SHA512withRSA");
    
    private final String algorithmName;
    
    private SignatureType(String algorithmName)
    {
	this.algorithmName=algorithmName;
    }
    
    public String getAlgorithmName()
    {
	return algorithmName;
    }
    
    public Signature getSignatureInstance() throws NoSuchAlgorithmException
    {
	return Signature.getInstance(algorithmName);
    }
    
    public int getSignatureSizeBytes(int keySize)
    {
	return keySize/8;
    }
    public int getSignatureSizeBits(int keySize)
    {
	return keySize;
    }
}

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

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

/**
 * 
 * @author Jason Mahdjoub
 * @version 1.1
 * @since Utils 1.4
 */
public class ASymmetricEncryptionAlgorithm extends AbstractEncryptionIOAlgorithm
{
    private final KeyPair myKeyPair;
    private final PublicKey distantPublicKey;
    private final Signature signature;
    private final ASymmetricEncryptionType type;
    
    public ASymmetricEncryptionAlgorithm(ASymmetricEncryptionType type, KeyPair myKeyPair, PublicKey distantPublicKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException
    {
	this(type, type.getDefaultSignatureAlgorithm().getSignatureInstance(), myKeyPair, distantPublicKey);
    }
    
    public ASymmetricEncryptionAlgorithm(ASymmetricEncryptionType type, Signature signature, KeyPair myKeyPair, PublicKey distantPublicKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException
    {
	super(type.getCipherInstance());
	if (signature==null)
	    throw new NullPointerException("signature");
	if (myKeyPair==null)
	    throw new NullPointerException("myKeyPair");
	if (distantPublicKey==null)
	    throw new NullPointerException("distantPublicKey");
	
	this.type=type;
	this.myKeyPair=myKeyPair;
	this.distantPublicKey=distantPublicKey;
	this.signature=signature;
	initCipherForEncrypt(this.cipher);
    }

    @Override
    public void initCipherForEncrypt(Cipher _cipher) throws InvalidKeyException
    {
	_cipher.init(Cipher.ENCRYPT_MODE, distantPublicKey);
	
    }

    @Override
    public void initCipherForDecrypt(Cipher _cipher) throws InvalidKeyException
    {
	_cipher.init(Cipher.DECRYPT_MODE, myKeyPair.getPrivate());
    }

    @Override
    protected Cipher getCipherInstance() throws NoSuchAlgorithmException, NoSuchPaddingException
    {
	return type.getCipherInstance();
    }
    
    public byte[] sign(byte bytes[]) throws InvalidKeyException, SignatureException
    {
	return this.sign(bytes, 0, bytes.length);
    }
    public byte[] sign(byte bytes[], int off, int len) throws InvalidKeyException, SignatureException
    {
	signature.initSign(myKeyPair.getPrivate());
	signature.update(bytes, off, len);
	return signature.sign();
    }

    public void sign(byte message[], int offm, int lenm, byte signature[], int off_sig, int len_sig) throws InvalidKeyException, SignatureException
    {
	this.signature.initSign(myKeyPair.getPrivate());
	this.signature.update(message, offm, lenm);
	this.signature.sign(signature, off_sig, len_sig);
    }
    
    public boolean verify(byte message[], byte signature[]) throws SignatureException, InvalidKeyException
    {
	return this.verify(message, 0, message.length, signature, 0, signature.length);
    }
    public boolean verify(byte message[], int offm, int lenm, byte signature[], int offs, int lens) throws SignatureException, InvalidKeyException
    {
	this.signature.initVerify(distantPublicKey);
	this.signature.update(message, offm, lenm);
	
	return this.signature.verify(signature, offs, lens);
    }
    
}

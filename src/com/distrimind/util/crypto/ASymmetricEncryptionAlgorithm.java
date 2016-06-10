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
    
    public KeyPair getMyKeyPair()
    {
	return this.myKeyPair;
    }
    
    public PublicKey getDistantPublicKey()
    {
	return this.distantPublicKey;
    }
}

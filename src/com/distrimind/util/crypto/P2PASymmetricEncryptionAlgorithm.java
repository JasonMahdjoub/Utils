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
import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

/**
 * 
 * @author Jason Mahdjoub
 * @version 1.4
 * @since Utils 1.4
 */
public class P2PASymmetricEncryptionAlgorithm extends AbstractEncryptionIOAlgorithm
{
    private final ASymmetricKeyPair myKeyPair;
    private final ASymmetricPublicKey distantPublicKey;
    private final SignerAlgorithm signer;
    private final SignatureCheckerAlgorithm signatureChecker;
    private final ASymmetricEncryptionType type;
    private final SignatureType signatureType;
    private final int maxBlockSizeForEncoding, maxBlockSizeForDecoding;
    
    public P2PASymmetricEncryptionAlgorithm(ASymmetricKeyPair myKeyPair, ASymmetricPublicKey distantPublicKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException
    {
	this(myKeyPair.getAlgorithmType().getDefaultSignatureAlgorithm(), myKeyPair, distantPublicKey);
    }

    public P2PASymmetricEncryptionAlgorithm(SignatureType signatureType, ASymmetricKeyPair myKeyPair, ASymmetricPublicKey distantPublicKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException
    {
	super(myKeyPair.getAlgorithmType().getCipherInstance());
	if (signatureType==null)
	    throw new NullPointerException("signatureType");
	if (distantPublicKey==null)
	    throw new NullPointerException("distantPublicKey");
	
	this.type=myKeyPair.getAlgorithmType();
	this.myKeyPair=myKeyPair;
	this.distantPublicKey=distantPublicKey;
	this.signatureType=signatureType;
	this.signer=new SignerAlgorithm(signatureType, myKeyPair.getASymmetricPrivateKey());
	this.signatureChecker=new SignatureCheckerAlgorithm(signatureType, distantPublicKey);
	//initCipherForEncrypt(this.cipher);
	this.maxBlockSizeForEncoding=myKeyPair.getMaxBlockSize();
	initCipherForDecrypt(this.cipher, null);
	this.maxBlockSizeForDecoding=cipher.getOutputSize(this.maxBlockSizeForEncoding);
    }
    
    public SignatureType getSignatureType()
    {
	return signatureType;
    }

    @Override
    public void initCipherForEncrypt(Cipher _cipher) throws InvalidKeyException
    {
	initCipherForEncryptAndNotChangeIV(_cipher);
    }
    @Override
    public void initCipherForEncryptAndNotChangeIV(Cipher _cipher) throws InvalidKeyException
    {
	_cipher.init(Cipher.ENCRYPT_MODE, distantPublicKey.getPublicKey());
	
    }

    @Override
    public void initCipherForDecrypt(Cipher _cipher, byte[] iv) throws InvalidKeyException
    {
	_cipher.init(Cipher.DECRYPT_MODE, myKeyPair.getASymmetricPrivateKey().getPrivateKey());
    }

    @Override
    protected Cipher getCipherInstance() throws NoSuchAlgorithmException, NoSuchPaddingException
    {
	return type.getCipherInstance();
    }
    
    public SignerAlgorithm getSignerAlgorithm()
    {
	return signer;
    }

    public SignatureCheckerAlgorithm getSignatureCheckerAlgorithm()
    {
	return signatureChecker;
    }
    
    public ASymmetricKeyPair getMyKeyPair()
    {
	return this.myKeyPair;
    }
    
    public ASymmetricPublicKey getDistantPublicKey()
    {
	return this.distantPublicKey;
    }

    @Override
    public int getMaxBlockSizeForEncoding()
    {
	return maxBlockSizeForEncoding;
    }
    @Override
    public int getMaxBlockSizeForDecoding()
    {
	return maxBlockSizeForDecoding;
    }

    @Override
    protected boolean includeIV()
    {
	return false;
    }
    
}

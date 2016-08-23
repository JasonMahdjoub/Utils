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
import java.security.Signature;
import java.security.SignatureException;

/**
 * 
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 1.7
 */
public class SignatureCheckerAlgorithm
{
    private final ASymmetricPublicKey distantPublicKey;
    private final Signature signature;
    
    public SignatureCheckerAlgorithm(ASymmetricPublicKey distantPublicKey) throws NoSuchAlgorithmException
    {
	this(distantPublicKey.getAlgorithmType().getDefaultSignatureAlgorithm().getSignatureInstance(), distantPublicKey);
    }
    
    public SignatureCheckerAlgorithm(SignatureType type, ASymmetricPublicKey distantPublicKey) throws NoSuchAlgorithmException
    {
	this(type.getSignatureInstance(), distantPublicKey);
    }

    public SignatureCheckerAlgorithm(Signature signature, ASymmetricPublicKey distantPublicKey)
    {
	if (signature==null)
	    throw new NullPointerException("signature");
	if (distantPublicKey==null)
	    throw new NullPointerException("distantPublicKey");
	this.distantPublicKey=distantPublicKey;
	this.signature=signature;
    }
    
    public ASymmetricPublicKey getDistantPublicKey()
    {
	return distantPublicKey;
    }
    
    public boolean verify(byte message[], byte signature[]) throws SignatureException, InvalidKeyException
    {
	return this.verify(message, 0, message.length, signature, 0, signature.length);
    }
    public boolean verify(byte message[], int offm, int lenm, byte signature[], int offs, int lens) throws SignatureException, InvalidKeyException
    {
	this.signature.initVerify(distantPublicKey.getPublicKey());
	this.signature.update(message, offm, lenm);
	
	return this.signature.verify(signature, offs, lens);
    }
    
}

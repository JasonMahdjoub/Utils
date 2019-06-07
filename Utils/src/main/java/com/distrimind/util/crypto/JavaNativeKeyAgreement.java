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

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.KeyAgreement;
import javax.crypto.ShortBufferException;


/**
 * 
 * @author Jason Mahdjoub
 * @version 2.0
 * @since Utils 3.10.0
 */
public final class JavaNativeKeyAgreement extends AbstractKeyAgreement {

	private final KeyAgreement keyAgreement;
	
	
	JavaNativeKeyAgreement(SymmetricEncryptionType encryptionType, KeyAgreement keyAgreement) {
		super(encryptionType);
		this.keyAgreement = keyAgreement;
	}
	
	JavaNativeKeyAgreement(SymmetricAuthentifiedSignatureType signatyreType, KeyAgreement keyAgreement) {
		super(signatyreType);
		this.keyAgreement = keyAgreement;
	}


	@Override
	public void doPhase(Key key, boolean lastPhase) throws IllegalStateException, InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException {
		
		this.keyAgreement.doPhase(key.toJavaNativeKey(), lastPhase);
	}


	@Override
	public byte[] generateSecret() throws IllegalStateException {
		
		return this.keyAgreement.generateSecret();
	}


	@Override
	public int generateSecret(byte[] sharedSecret, int offset) throws IllegalStateException, ShortBufferException {
		return this.keyAgreement.generateSecret(sharedSecret, offset);
	}


	@SuppressWarnings("ConstantConditions")
    @Override
	public SymmetricSecretKey generateSecretKey(short keySize)
			throws InvalidKeyException, NoSuchAlgorithmException {
		if (encryptionType==null)
		{
			return new SymmetricSecretKey(signatureType, this.keyAgreement.generateSecret(signatureType.getAlgorithmName()+"["+keySize+"]"), keySize);
		}
		else
			return new SymmetricSecretKey(encryptionType, this.keyAgreement.generateSecret(encryptionType.getAlgorithmName()+"["+keySize+"]"), keySize);
	}


	@Override
	public String getAlgorithm() {
		
		return keyAgreement.getAlgorithm();
	}



	@Override
	public void init(Key key, Object params, AbstractSecureRandom random)
			throws InvalidAlgorithmParameterException, InvalidKeyException, NoSuchAlgorithmException,InvalidKeySpecException  {
		
		keyAgreement.init(key.toJavaNativeKey(), (AlgorithmParameterSpec)params, random);

	}



	

}

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

import com.distrimind.util.io.Integrity;
import com.distrimind.util.io.MessageExternalizationException;

import java.io.IOException;
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
	public void doPhase(AbstractKey key, boolean lastPhase) throws IOException {

		try {
			this.keyAgreement.doPhase(key.toJavaNativeKey(), lastPhase);
		} catch (InvalidKeyException | InvalidKeySpecException e) {
			throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN, e);
		} catch (NoSuchAlgorithmException e) {
			throw new MessageExternalizationException(Integrity.FAIL, e);
		}
	}


	@Override
	public byte[] generateSecret() {
		
		return this.keyAgreement.generateSecret();
	}


	@Override
	public int generateSecret(byte[] sharedSecret, int offset) throws IOException {
		try {
			return this.keyAgreement.generateSecret(sharedSecret, offset);
		} catch (ShortBufferException e) {
			throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN, e);
		}
	}


	@SuppressWarnings("ConstantConditions")
    @Override
	public SymmetricSecretKey generateSecretKey(short keySize)
			throws IOException {
		try {
			if (encryptionType == null) {
				return new SymmetricSecretKey(signatureType, this.keyAgreement.generateSecret("AES[" + keySize + "]"), keySize);
			} else
				return new SymmetricSecretKey(encryptionType, this.keyAgreement.generateSecret(encryptionType.getAlgorithmName() + "[" + keySize + "]"), keySize);
		} catch (NoSuchAlgorithmException e) {
			throw new MessageExternalizationException(Integrity.FAIL, e);
		} catch (InvalidKeyException e) {
			throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN, e);
		}
	}


	@Override
	public String getAlgorithm() {
		
		return keyAgreement.getAlgorithm();
	}



	@Override
	public void init(AbstractKey key, Object params, AbstractSecureRandom random)
			throws IOException  {

		try {
			keyAgreement.init(key.toJavaNativeKey(), (AlgorithmParameterSpec)params, random);
		} catch (InvalidKeyException | InvalidKeySpecException | InvalidAlgorithmParameterException e) {
			throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN, e);
		} catch (NoSuchAlgorithmException e) {
			throw new MessageExternalizationException(Integrity.FAIL, e);
		}

	}



	

}

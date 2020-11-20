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
import com.distrimind.bouncycastle.crypto.CryptoException;

import java.io.IOException;
import java.util.Arrays;

/**
 *
 * @author Jason Mahdjoub
 * @version 1.2
 * @since Utils 3.15.0
 */
public class P2PLoginWithSymmetricSignature extends P2PLoginAgreement {

	private final SymmetricSecretKey secretKey;
	private byte[] myMessage, otherMessage=null;
	private static final int messageSize=32;
	private boolean valid=true;

	@Override
	public void zeroize() {
		if (myMessage!=null)
			Arrays.fill(myMessage, (byte)0);
		if (otherMessage!=null)
			Arrays.fill(otherMessage, (byte)0);
		myMessage=null;
		otherMessage=null;
	}

	@Override
	public boolean isPostQuantumAgreement() {
		return secretKey!=null && secretKey.isPostQuantumKey();
	}

	P2PLoginWithSymmetricSignature(SymmetricSecretKey secretKey, AbstractSecureRandom random) {
		super(2, 2);
		if (secretKey==null)
			throw new NullPointerException();
		if (secretKey.getAuthenticatedSignatureAlgorithmType()==null)
			throw new IllegalArgumentException("The given secret key is not usable for signature");
		this.secretKey=secretKey;
		myMessage=new byte[messageSize];
		random.nextBytes(myMessage);

	}

	@Override
	protected boolean isAgreementProcessValidImpl() {
		return valid;
	}

	@Override
	protected byte[] getDataToSend(int stepNumber) throws IOException {
		if (!valid)
			throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN, new CryptoException());

		try {
			switch (stepNumber) {
				case 0:
					return myMessage;
				case 1: {
					if (otherMessage == null) {
						valid = false;
						throw new IllegalAccessError();
					}
					SymmetricAuthenticatedSignerAlgorithm signer = new SymmetricAuthenticatedSignerAlgorithm(secretKey);
					signer.init();
					signer.update(myMessage);
					signer.update(otherMessage);
					return signer.getSignature();

				}
				default:
					valid = false;
					throw new IllegalAccessError();
			}
		}
		catch(Exception e)
		{
			valid=false;
			throw new MessageExternalizationException(Integrity.FAIL, e);
		}

	}

	@Override
	protected void receiveData(int stepNumber, byte[] data) throws IOException {
		try {
			if (!valid)
				throw new CryptoException();
			switch (stepNumber) {
				case 0: {
					if (otherMessage != null) {
						valid = false;
						throw new CryptoException();
					}
					if (data.length != messageSize) {
						valid = false;
						throw new CryptoException();
					}
					otherMessage = data;
				}
				break;
				case 1: {
					if (otherMessage == null) {
						valid = false;
						throw new CryptoException();
					}
					SymmetricAuthenticatedSignatureCheckerAlgorithm checker = new SymmetricAuthenticatedSignatureCheckerAlgorithm(secretKey);
					checker.init(data);
					checker.update(otherMessage);
					checker.update(myMessage);

					valid = checker.verify();
				}
				break;
				default:
					valid = false;
					throw new CryptoException("" + stepNumber);
			}
		}
		catch (Exception e)
		{
			valid = false;
			if (e instanceof CryptoException)
				throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN, e);
			else
				throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN, new CryptoException("", e));
		}
	}



}

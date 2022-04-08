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


import com.distrimind.bouncycastle.crypto.CryptoException;
import com.distrimind.util.Cleanable;
import com.distrimind.util.io.Integrity;
import com.distrimind.util.io.MessageExternalizationException;

import java.io.IOException;
import java.util.Arrays;

/**
 *
 * @author Jason Mahdjoub
 * @version 1.3
 * @since Utils 3.15.0
 */
public abstract class AbstractP2PLoginWithSignature extends P2PLoginAgreement {
	private static final class Finalizer extends Cleaner
	{
		private byte[] myMessage, otherMessage=null;

		private Finalizer(Cleanable cleanable) {
			super(cleanable);
		}

		@Override
		protected void performCleanup() {
			if (myMessage!=null)
				Arrays.fill(myMessage, (byte)0);
			if (otherMessage!=null)
				Arrays.fill(otherMessage, (byte)0);
			myMessage=null;
			otherMessage=null;
		}
	}
	private final Finalizer finalizer;
	private final AbstractAuthenticatedSignerAlgorithm signer;
	private final AbstractAuthenticatedCheckerAlgorithm checker;

	private boolean valid=true;
	private final static byte[] emptyTab=new byte[0];

	AbstractP2PLoginWithSignature(AbstractSecureRandom random, AbstractAuthenticatedSignerAlgorithm signer, AbstractAuthenticatedCheckerAlgorithm checker) {
		super(2, 2);
		if (checker==null && signer==null)
			throw new NullPointerException();
		this.finalizer=new Finalizer(this);
		finalizer.myMessage=new byte[messageSize];
		random.nextBytes(finalizer.myMessage);
		this.signer=signer;
		this.checker=checker;
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
					return finalizer.myMessage;
				case 1: {
					if (finalizer.otherMessage == null) {
						valid = false;
						throw new IllegalAccessError();
					}
					if (signer==null)
						return emptyTab;
					return generateSignature(finalizer.myMessage, finalizer.otherMessage, signer);
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
					if (finalizer.otherMessage != null) {
						valid = false;
						throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN, new CryptoException());
					}
					checkCompatibleMessages(finalizer.myMessage, data);

					finalizer.otherMessage = data;
				}
				break;
				case 1: {
					if (finalizer.otherMessage == null) {
						valid = false;
						throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN, new CryptoException());
					}
					if (checker==null) {
						if (data.length!=0)
							throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN, new CryptoException());
					}
					else
						valid=checkSignature(finalizer.myMessage, finalizer.otherMessage, checker, data, 0, data.length);
				}
				break;
				default:
					valid = false;
					throw new CryptoException("" + stepNumber);
			}
		}
		catch (MessageExternalizationException e)
		{
			valid = false;
			throw e;
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

	@Override
	public boolean isPostQuantumAgreement() {
		return (signer==null || signer.isPostQuantumSigner()) && (checker==null || checker.isPostQuantumChecker());
	}
}

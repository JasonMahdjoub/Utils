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


import com.distrimind.util.Cleanable;
import com.distrimind.util.io.Integrity;
import com.distrimind.util.io.MessageExternalizationException;
import com.distrimind.bouncycastle.crypto.CryptoException;
import com.distrimind.bouncycastle.pqc.crypto.ExchangePair;
import com.distrimind.bouncycastle.pqc.crypto.newhope.NHPublicKeyParameters;

import java.io.IOException;
import java.util.Arrays;

/**
 *
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 3.10.0
 */
public abstract class AbstractNewHopeKeyAgreementServer extends AbstractNewHopeKeyAgreement{
	private static final class Finalizer extends Cleaner
	{
		private ExchangePair exchangePair;

		private Finalizer(Cleanable cleanable) {
			super(cleanable);
		}

		@Override
		protected void performCleanup() {
			if (exchangePair!=null) {
				Arrays.fill(exchangePair.getSharedValue(), (byte) 0);
				exchangePair = null;
			}
		}
	}
	private final Finalizer finalizer;
	private final AbstractSecureRandom randomForKeys;

	private boolean valid=true;

	@Override
	public boolean isPostQuantumAgreement() {
		return true;
	}

	protected AbstractNewHopeKeyAgreementServer(SymmetricAuthenticatedSignatureType symmetricAuthenticatedSignatureType, SymmetricEncryptionType symmetricEncryptionType, AbstractSecureRandom randomForKeys) {
		this(symmetricAuthenticatedSignatureType, symmetricEncryptionType, (short)256, randomForKeys);
	}
	protected AbstractNewHopeKeyAgreementServer(SymmetricAuthenticatedSignatureType symmetricAuthenticatedSignatureType, SymmetricEncryptionType symmetricEncryptionType, short keySizeBits, AbstractSecureRandom randomForKeys) {
		super(symmetricAuthenticatedSignatureType, symmetricEncryptionType, (short)(keySizeBits/8));
		this.randomForKeys=randomForKeys;
		this.finalizer=new Finalizer(this);
	}



	public void setDataPhase1(byte []data)
	{
		valid=false;
		byte[] sharedValue = new byte[agreementSize];
		byte[] publicKeyValue = new byte[SENDB_BYTES];

		AbstractNewHopeKeyAgreement.sharedB(randomForKeys, sharedValue, publicKeyValue, data);


		finalizer.exchangePair=new ExchangePair(new NHPublicKeyParameters(publicKeyValue), sharedValue);
		super.finalizer.shared=finalizer.exchangePair.getSharedValue();
		assert super.finalizer.shared!=null;
		valid=true;
	}

	public byte[] getDataPhase2()
	{
		valid=false;
		byte[] res= ((NHPublicKeyParameters)finalizer.exchangePair.getPublicKey()).getPubData();
		valid=true;
		return res;
	}

	@Override
	public boolean isAgreementProcessValidImpl() {
		return valid;
	}
	@Override
	protected byte[] getDataToSend(int stepNumber) throws IOException {
		if (!valid)
			throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN, new CryptoException());

		try {
			if (stepNumber == 0)
				return getDataPhase2();
			else {
				valid = false;
				throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN,new IllegalAccessException());
			}
		}
		catch(Exception e)
		{
			valid=false;
			throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN, e);
		}


	}
	@Override
	protected void receiveData(int stepNumber, byte[] data) throws IOException {
		if (!valid)
			throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN, new CryptoException());

		try {
			if (stepNumber == 0)
				setDataPhase1(data);
			else
				throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN, new IllegalAccessException());
		}
		catch(Exception e)
		{
			valid=false;
			throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN, new CryptoException("", e));
		}


	}



}

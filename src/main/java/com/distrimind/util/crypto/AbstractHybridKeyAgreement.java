package com.distrimind.util.crypto;
/*
Copyright or © or Corp. Jason Mahdjoub (01/04/2013)

jason.mahdjoub@distri-mind.fr

This software (Object Oriented Database (OOD)) is a computer program 
whose purpose is to manage a local database with the object paradigm 
and the java language

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

import com.distrimind.bouncycastle.crypto.CryptoException;
import com.distrimind.util.Bits;
import com.distrimind.util.Cleanable;
import com.distrimind.util.io.Integrity;
import com.distrimind.util.io.MessageExternalizationException;

import java.io.IOException;

/**
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 4.5.0
 */
abstract class AbstractHybridKeyAgreement<KA extends IKeyAgreement> extends Agreement implements IKeyAgreement {

	private static class Finalizer<KA extends IAgreement> extends Cleaner
	{
		private KA nonPQCKeyAgreement, PQCKeyAgreement;
		private SymmetricSecretKey secretKey=null;
		private SymmetricSecretKeyPair secretKeyPair=null;

		protected Finalizer(Cleanable cleanable) {
			super(cleanable);
		}

		@Override
		protected void performCleanup() {
			if (nonPQCKeyAgreement!=null) {
				nonPQCKeyAgreement.clean();
				nonPQCKeyAgreement=null;
			}
			if (PQCKeyAgreement!=null) {
				PQCKeyAgreement.clean();
				PQCKeyAgreement=null;
			}
			if (secretKey!=null) {
				this.secretKey = null;
			}
			if (secretKeyPair!=null) {
				this.secretKeyPair = null;
			}
		}
	}
	private final Finalizer<KA> finalizer;


	protected AbstractHybridKeyAgreement(KA nonPQCKeyAgreement, KA PQCKeyAgreement)
	{
		super(Math.max(nonPQCKeyAgreement.getStepsNumberForReception(),PQCKeyAgreement.getStepsNumberForReception())
				, Math.max(nonPQCKeyAgreement.getStepsNumberForSend(),PQCKeyAgreement.getStepsNumberForSend()));
		if (PQCKeyAgreement.getDerivedKeySizeBytes()<32)
			throw new IllegalArgumentException("Derived key size of PQC algorithm must be greater than 256 bits");
		if (nonPQCKeyAgreement.isPostQuantumAgreement())
			throw new IllegalArgumentException();
		if (!PQCKeyAgreement.isPostQuantumAgreement())
			throw new IllegalArgumentException();
		finalizer= new Finalizer<>(this);
		this.finalizer.nonPQCKeyAgreement=nonPQCKeyAgreement;
		this.finalizer.PQCKeyAgreement=PQCKeyAgreement;
	}


	protected SymmetricSecretKey getDerivedKey() {
		return finalizer.secretKey;
	}
	protected SymmetricSecretKeyPair getDerivedSecretKeyPair() {
		return finalizer.secretKeyPair;
	}

	@Override
	public short getDerivedKeySizeBytes() {
		return  finalizer.PQCKeyAgreement.getDerivedKeySizeBytes();
	}


	private void checkSymmetricSecretKey() throws IOException
	{
		if (finalizer.secretKey==null && hasFinishedReception() && hasFinishedSend() && isAgreementProcessValid())
		{
			if (this instanceof ISimpleKeyAgreement) {
				SymmetricSecretKey nonPQC = ((ISimpleKeyAgreement)finalizer.nonPQCKeyAgreement).getDerivedSecretKey();
				SymmetricSecretKey PQC = ((ISimpleKeyAgreement)finalizer.PQCKeyAgreement).getDerivedSecretKey();
				finalizer.secretKey = SymmetricSecretKey.getDerivedKey(nonPQC, PQC);
			}
			else if (this instanceof IDualKeyAgreement){
				SymmetricSecretKeyPair nonPQC = ((IDualKeyAgreement)finalizer.nonPQCKeyAgreement).getDerivedSecretKeyPair();
				SymmetricSecretKeyPair PQC = ((IDualKeyAgreement)finalizer.PQCKeyAgreement).getDerivedSecretKeyPair();

				finalizer.secretKeyPair=SymmetricSecretKeyPair.getDerivedKey(nonPQC, PQC);

			}
			else
				throw new IllegalAccessError();
		}
	}

	@Override
	public boolean isAgreementProcessValidImpl() {
		return finalizer.nonPQCKeyAgreement.isAgreementProcessValidImpl() && finalizer.PQCKeyAgreement.isAgreementProcessValidImpl();
	}

	@Override
	protected byte[] getDataToSend(int stepNumber) throws IOException {
		try {
			byte[] nonPQC = null, PQC = null;
			boolean nonPQCb=false, PQCb=false;
			if (!finalizer.nonPQCKeyAgreement.hasFinishedSend()) {
				nonPQC = finalizer.nonPQCKeyAgreement.getDataToSend();
				nonPQCb = true;
			}
			if (!finalizer.PQCKeyAgreement.hasFinishedSend()) {
				PQC = finalizer.PQCKeyAgreement.getDataToSend();
				PQCb = true;
			}
			if (nonPQCb && PQCb) {
				byte[] res = new byte[nonPQC.length + PQC.length + 3];
				Bits.putUnsignedInt(res, 0, nonPQC.length, 3);
				System.arraycopy(nonPQC, 0, res, 3, nonPQC.length);
				System.arraycopy(PQC, 0, res, 3 + nonPQC.length, PQC.length);
				return res;
			} else if (nonPQCb)
				return nonPQC;
			else
				return PQC;
		}
		finally {
			checkSymmetricSecretKey();
		}
	}

	KA getNonPQCKeyAgreement() {
		return finalizer.nonPQCKeyAgreement;
	}

	KA getPQCKeyAgreement() {
		return finalizer.PQCKeyAgreement;
	}

	@Override
	protected void receiveData(int stepNumber, byte[] data) throws IOException {
		try {
			byte[] nonPQC = null, PQC = null;
			if (!finalizer.nonPQCKeyAgreement.hasFinishedReception() && !finalizer.PQCKeyAgreement.hasFinishedReception()) {
				int s = (int) Bits.getUnsignedInt(data, 0, 3);
				if (s + 36 > data.length)
					throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN, new CryptoException());
				nonPQC = new byte[s];
				PQC = new byte[data.length - s - 3];
				System.arraycopy(data, 3, nonPQC, 0, nonPQC.length);
				System.arraycopy(data, 3 + s, PQC, 0, PQC.length);
			} else if (!finalizer.nonPQCKeyAgreement.hasFinishedReception())
				nonPQC = data;
			else
				PQC = data;
			if (!finalizer.nonPQCKeyAgreement.hasFinishedReception())
				finalizer.nonPQCKeyAgreement.receiveData(nonPQC);
			if (!finalizer.PQCKeyAgreement.hasFinishedReception())
				finalizer.PQCKeyAgreement.receiveData(PQC);
		}
		finally
		{
			checkSymmetricSecretKey();
		}

	}


	@Override
	public boolean isPostQuantumAgreement() {
		return true;
	}
}

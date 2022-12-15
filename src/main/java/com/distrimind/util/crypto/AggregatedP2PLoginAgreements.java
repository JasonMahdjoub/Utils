/*
Copyright or © or Corp. Jason Mahdjoub (04/02/2016)

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

import java.io.IOException;

/**
 *
 * @author Jason Mahdjoub
 * @version 3.0
 * @since Utils 3.15.0
 */
public class AggregatedP2PLoginAgreements extends P2PLoginAgreement {
	private final static class Finalizer extends Cleaner
	{
		private P2PLoginAgreement[] loginAgreements;

		private Finalizer(Cleanable cleanable) {
			super(cleanable);
		}

		@Override
		protected void performCleanup() {
			if (loginAgreements!=null) {
				for (P2PLoginAgreement la: loginAgreements)
					la.clean();
				loginAgreements=null;
			}
		}
	}
	private final Finalizer finalizer;

	@Override
	public boolean isPostQuantumAgreement() {
		for (P2PLoginAgreement p : finalizer.loginAgreements) {
			if (!p.isPostQuantumAgreement())
				return false;
		}
		return true;
	}
	private static int getStepsNumberForSend(P2PLoginAgreement[] loginAgreements) {
		if (loginAgreements==null)
			throw new NullPointerException();
		if (loginAgreements.length==0)
			throw new IllegalArgumentException();
		int res=0;
		for (P2PLoginAgreement la : loginAgreements)
		{
			if (la == null)
				throw new NullPointerException();
			res+=la.getStepsNumberForSend();
		}
		return res;
	}
	private static int getStepsNumberForReception(P2PLoginAgreement[] loginAgreements) {
		if (loginAgreements==null)
			throw new NullPointerException();
		if (loginAgreements.length==0)
			throw new IllegalArgumentException();
		int res=0;
		for (P2PLoginAgreement la : loginAgreements)
		{
			if (la == null)
				throw new NullPointerException();
			res+=la.getStepsNumberForReception();
		}
		return res;
	}

	AggregatedP2PLoginAgreements(P2PLoginAgreement ...loginAgreements)
	{
		super(getStepsNumberForReception(loginAgreements), getStepsNumberForSend(loginAgreements));
		this.finalizer=new Finalizer(this);
		this.finalizer.loginAgreements=loginAgreements;
	}
	@Override
	public boolean isAgreementProcessValidImpl() {

		for (P2PLoginAgreement p : finalizer.loginAgreements) {
			if (!p.isAgreementProcessValidImpl())
				return false;
		}
		return true;
	}
	@Override
	protected byte[] getDataToSend(int stepNumber) throws IOException {
		int off=0;
		for (P2PLoginAgreement loginAgreement : finalizer.loginAgreements) {
			off += loginAgreement.getStepsNumberForSend();
			if (off > stepNumber)
				return loginAgreement.getDataToSend();
		}
		throw new IllegalAccessError();
	}
	@Override
	protected void receiveData(int stepNumber, byte[] data) throws IOException {
		int off=0;
		for (P2PLoginAgreement loginAgreement : finalizer.loginAgreements) {
			off += loginAgreement.getStepsNumberForReception();
			if (off > stepNumber) {
				loginAgreement.receiveData(data);
				return;
			}
		}
		throw new IllegalAccessError();

	}

}

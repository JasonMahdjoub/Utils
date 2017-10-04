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

/**
 * 
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 3.0
 */
public abstract class Agreement {
	
	private int actualStepForReceiption, actualStepForSend;
	private final int stepsNumberForReceiption;
	private final int stepsNumberForSend;
	protected Agreement(int stepsNumberForReceiption, int stepsNumberForSend)
	{
		actualStepForReceiption=0;
		actualStepForSend=0;
		this.stepsNumberForReceiption=stepsNumberForReceiption;
		this.stepsNumberForSend=stepsNumberForSend;
	}
	
	public int getActualStepForReceiptionIndex()
	{
		return actualStepForReceiption;
	}
	public int getActualStepForSendIndex()
	{
		return actualStepForSend;
	}
	
	public int getStepsNumberForReceiption()
	{
		return stepsNumberForReceiption;
	}
	public int getStepsNumberForSend()
	{
		return stepsNumberForSend;
	}
	
	public boolean hasFinishedSend()
	{
		return stepsNumberForSend==actualStepForSend;
	}
	public boolean hasFinishedReceiption()
	{
		return stepsNumberForReceiption==actualStepForReceiption;
	}
	
	public boolean isAgreementProcessValid()
	{
		return hasFinishedReceiption() && hasFinishedSend() && isAgreementProcessValidImpl();
	}
	
	protected abstract boolean isAgreementProcessValidImpl(); 
	
	public byte[] getDataToSend() throws Exception
	{
		if (hasFinishedSend())
			throw new IllegalAccessException("The process has finished");
		return getDataToSend(actualStepForSend++);
	}
	public void receiveData(byte data[]) throws Exception
	{
		if (hasFinishedReceiption())
			throw new IllegalAccessException("The process has finished");
		receiveData(actualStepForReceiption++, data);
	}

	protected abstract byte[] getDataToSend(int stepNumber) throws Exception;
	protected abstract void receiveData(int stepNumber, byte data[]) throws Exception;
}

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

import com.distrimind.util.systeminfo.State;
import com.distrimind.util.systeminfo.SystemInfo;

import java.io.IOException;

/**
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 5.24.0
 */
public interface IClientServer {
	default AbstractWrappedIVs<?, ?> getWrappedIVAndSecretKeyInstance() throws IOException {
		return null;
	}
	AbstractCipher getCipherInstance() throws IOException;
	int getMaxPlainTextSizeForEncoding();
	boolean isPostQuantumEncryption();
	void checkKeysNotCleaned();

	default boolean isPowerMonitoringSideChannelAttackMitigationActivated(){
		State state=SystemInfo.getInstance().getPowerMonitoringAttackMitigationState();
		if (state==State.ENABLED)
			return true;
		else if (state==State.DISABLED)
			return false;
		else
		{
			return SystemInfo.getInstance().isPowerMonitoringAttackPossibleIntoCurrentCPU();
		}
	}
	default boolean isFrequencySideChannelAttackMitigationActivated(){
		State state= SystemInfo.getInstance().getFrequencyAttackMitigationState();
		if (state==State.ENABLED)
			return true;
		else if (state==State.DISABLED)
			return false;
		else
		{
			return SystemInfo.getInstance().isFrequencyAttackPossibleIntoCurrentCPU();
		}
	}
	default boolean isTimingSideChannelAttackMitigationActivated()
	{
		State state=SystemInfo.getInstance().getTimingAttackMitigationState();
		if (state==State.ENABLED)
			return true;
		else if (state==State.DISABLED)
			return false;
		else
		{
			return SystemInfo.getInstance().isTimingAttackPossibleIntoCurrentCPU();
		}
	}
	default boolean isUsingSideChannelMitigation()
	{
		return isPowerMonitoringSideChannelAttackMitigationActivated() || isFrequencySideChannelAttackMitigationActivated() || isTimingSideChannelAttackMitigationActivated();
	}
	int getIVSizeBytesWithExternalCounter();



	default int getIVSizeBytesWithoutExternalCounter()
	{
		return getIVSizeBytesWithExternalCounter()-(useExternalCounter()?getBlockModeCounterBytes():0);
	}
	default boolean useExternalCounter()
	{
		return false;
	}
	default byte getBlockModeCounterBytes() {
		return (byte)0;
	}

	default AbstractSecureRandom getSecureRandomForIV()
	{
		return null;
	}

	default AbstractSecureRandom getSecureRandomForKeyGeneration()
	{
		return null;
	}
}

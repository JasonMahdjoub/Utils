package com.distrimind.util.crypto;
/*
Copyright or © or Copr. Jason Mahdjoub (01/04/2013)

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

import com.distrimind.util.io.RandomInputStream;
import com.distrimind.util.io.RandomOutputStream;

import java.io.IOException;

/**
 * @author Jason Mahdjoub
 * @version 3.0
 * @since Utils 4.5.0
 */
interface IServer {


	int getMaxPlainTextSizeForEncoding();

	void initCipherForDecryption(AbstractCipher cipher)
			throws IOException;

	AbstractCipher getCipherInstance() throws IOException;


	boolean isPostQuantumEncryption();

	long getOutputSizeAfterDecryption(long inputLen)
			throws IOException;


	void decode(RandomInputStream is, byte[] associatedData, int offAD, int lenAD, RandomOutputStream os, int length, byte[] externalCounter)
			throws IOException;



	RandomInputStream getCipherInputStreamForDecryption(RandomInputStream is, byte[] externalCounter) throws IOException;
	byte[] decode(byte[] bytes, int off, int len, byte[] associatedData, int offAD, int lenAD, byte[] externalCounter)
			throws IOException;
	RandomInputStream getCipherInputStreamForDecryption(final RandomInputStream is, byte[] associatedData, int offAD, int lenAD, final byte[] externalCounter) throws IOException;
	void checkKeysNotCleaned();

	default boolean isPowerMonitoringSideChannelAttackPossible(){
		return true;
	}
	default boolean isFrequencySideChannelAttackPossible(){
		return true;
	}
	default boolean isTimingSideChannelAttackPossible()
	{
		return true;
	}
	default boolean isUsingSideChannelMitigation()
	{
		return isPowerMonitoringSideChannelAttackPossible() || isFrequencySideChannelAttackPossible() || isTimingSideChannelAttackPossible();
	}
	default CPUUsageAsDecoyInputStream<CommonCipherInputStream> getCPUUsageAsDecoyInputStream(CommonCipherInputStream in) throws IOException
	{
		return new CPUUsageAsDecoyInputStream<>(in);
	}
}

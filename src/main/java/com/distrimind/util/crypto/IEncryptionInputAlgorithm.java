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
 * @version 2.0
 * @since Utils 4.5.0
 */
public interface IEncryptionInputAlgorithm extends IServer{
	byte[] decode(byte[] bytes)
			throws IOException;
	byte[] decode(byte[] bytes, byte[] associatedData, byte[] externalCounter) throws IOException;
	byte[] decode(byte[] bytes, byte[] associatedData) throws IOException;
	byte[] decode(byte[] bytes, int off, int len) throws IOException;
	byte[] decode(byte[] bytes, int off, int len, byte[] associatedData, int offAD, int lenAD) throws IOException;
	byte[] decode(RandomInputStream is, byte[] associatedData) throws IOException;
	byte[] decode(RandomInputStream is) throws IOException;
	byte[] decode(RandomInputStream is, byte[] associatedData, int offAD, int lenAD) throws IOException;
	byte[] decode(RandomInputStream is, byte[] associatedData, int offAD, int lenAD, byte[] externalCounter)
			throws IOException;
	void decode(RandomInputStream is, byte[] associatedData, RandomOutputStream os) throws IOException;
	void decode(RandomInputStream is, RandomOutputStream os, byte[] externalCounter) throws IOException;
	void decode(RandomInputStream is, RandomOutputStream os) throws IOException;
	void decode(RandomInputStream is, byte[] associatedData, int offAD, int lenAD, RandomOutputStream os) throws IOException;
	void decode(RandomInputStream is, byte[] associatedData, int offAD, int lenAD, RandomOutputStream os, byte[] externalCounter) throws IOException;
	void decode(RandomInputStream is, RandomOutputStream os, int length) throws IOException;
	void decode(RandomInputStream is, RandomOutputStream os, int length, byte[] externalCounter) throws IOException;
	void decode(RandomInputStream is, byte[] associatedData, RandomOutputStream os, int length) throws IOException;
	void decode(RandomInputStream is, byte[] associatedData, int offAD, int lenAD, RandomOutputStream os, int length) throws IOException;
	void decode(RandomInputStream is, byte[] associatedData, int offAD, int lenAD, RandomOutputStream os, int length,  byte[] externalCounter) throws IOException;
	RandomInputStream getCipherInputStreamForDecryption(final RandomInputStream is) throws IOException ;
	RandomInputStream getCipherInputStreamForDecryption(final RandomInputStream is, byte[] externalCounter) throws IOException ;
	RandomInputStream getCipherInputStreamForDecryption(final RandomInputStream is, final byte[] associatedData, final int offAD, final int lenAD) throws IOException ;
	RandomInputStream getCipherInputStreamForDecryption(final RandomInputStream is, final byte[] associatedData, final int offAD, final int lenAD, byte[] externalCounter) throws IOException ;

	void initCipherForDecryption(AbstractCipher cipher) throws IOException;




}

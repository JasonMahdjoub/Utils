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

import javax.crypto.Cipher;
import java.io.DataInputStream;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Random;

/**
 * @author Jason Mahdjoub
 * @version 1.0
 * @since MaDKitLanEdition 5.24.0
 */
public class CPUUsageAsDecoyInputStream<T extends RandomInputStream> extends RandomInputStream {
	private final T in;
	private AbstractCipher cipher;

	private long wroteBytes=0;
	private long wroteFakeBytes=0;
	private final Random random=new Random(System.nanoTime());
	private final AbstractSecureRandom secureRandom;
	final static int BUFFER_SIZE = 4096;
	private final byte[] outputBuffer=new byte[BUFFER_SIZE];
	private final byte[] inputBuffer=new byte[BUFFER_SIZE-200];
	private final double falseCPUUsagePercentage= CPUUsageAsDecoyOutputStream.DEFAULT_FALSE_CPU_USAGE_PERCENTAGE;

	private final SymmetricEncryptionType symmetricEncryptionType;
	private final int opMode;
	public CPUUsageAsDecoyInputStream(T in) throws IOException {
		this(in, SymmetricEncryptionType.DEFAULT, Cipher.DECRYPT_MODE);
	}
	public CPUUsageAsDecoyInputStream(T in, SymmetricEncryptionType symType, int opMode) throws IOException {
		if (in==null)
			throw new NullPointerException();
		if (symType==null)
			throw new NullPointerException();
		this.in = in;
		this.symmetricEncryptionType=symType;
		this.opMode=opMode;
		try {
			secureRandom =SecureRandomType.DEFAULT.getSingleton(null);
		} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
			throw new IOException(e);
		}
		reset();
	}
	public void reset() throws IOException {
		try {
			cipher=symmetricEncryptionType.getCipherInstance();
			SymmetricSecretKey key = symmetricEncryptionType.getKeyGenerator(secureRandom).generateKey();
			byte[] iv=new byte[symmetricEncryptionType.getIVSizeBytes()];
			secureRandom.nextBytes(iv);
			cipher.init(opMode, key, iv);
		} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
			throw new IOException(e);
		}

	}

	@Override
	public long length() throws IOException {
		return in.length();
	}

	@Override
	public void seek(long _pos) throws IOException {
		in.seek(_pos);
	}

	@Override
	public boolean isClosed() {
		return in.isClosed();
	}

	@Override
	public void readFully(byte[] tab, int off, int len) throws IOException {
		RandomInputStream.checkLimits(tab,off,len);
		while (len>0) {
			int l = len<=AbstractEncryptionOutputAlgorithm.BUFFER_SIZE?secureRandom.nextInt((len/16)+1)*16:secureRandom.nextInt((len/128)+1)*128;
			if (l==0)
				l=len;
			long startNano=System.nanoTime();
			in.readFully(tab, off, l);
			off+=l;
			len-=l;
			wroteBytes+=l;
			wroteFakeBytes+= CPUUsageAsDecoyOutputStream.writeFakeBytes(cipher, secureRandom, random, wroteBytes, wroteFakeBytes, falseCPUUsagePercentage,inputBuffer, outputBuffer, System.nanoTime()-startNano);
		}
	}

	@Override
	@Deprecated
	public String readLine() throws IOException {
		return new DataInputStream(this).readLine();
	}

	@Override
	public int read() throws IOException {
		long startNano=System.nanoTime();
		int res=in.read();

		wroteFakeBytes+= CPUUsageAsDecoyOutputStream.writeFakeBytes(cipher, secureRandom, random, ++wroteBytes, wroteFakeBytes, falseCPUUsagePercentage,inputBuffer, outputBuffer, System.nanoTime()-startNano);
		return res;
	}

	/**
	 * {@inheritDoc}
	 *
	 */
	@Override
	public int read(byte[] tab, int off, int len) throws IOException {
		RandomInputStream.checkLimits(tab,off,len);
		int res=0;
		while (len>0) {
			int l = len<=AbstractEncryptionOutputAlgorithm.BUFFER_SIZE?secureRandom.nextInt((len/16)+1)*16:secureRandom.nextInt((len/128)+1)*128;
			if (l==0)
				l=len;
			long startNano=System.nanoTime();
			int r=in.read(tab, off, l);
			res+=r;
			off+=r;
			len-=r;
			wroteBytes+=r;
			wroteFakeBytes+= CPUUsageAsDecoyOutputStream.writeFakeBytes(cipher, secureRandom, random, wroteBytes, wroteFakeBytes, falseCPUUsagePercentage,inputBuffer, outputBuffer, System.nanoTime()-startNano);
			if (r!=l)
				break;
		}
		return res;
	}

	@Override
	public void close() throws IOException {
		in.close();
	}

	@Override
	public long currentPosition() throws IOException {
		return in.currentPosition();
	}

	public T getSourceRandomInputStream()
	{
		return in;
	}
}

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

import com.distrimind.util.Bits;
import com.distrimind.util.io.RandomInputStream;
import com.distrimind.util.io.RandomOutputStream;

import javax.crypto.Cipher;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Random;

/**
 * @author Jason Mahdjoub
 * @version 1.0
 * @since MaDKitLanEdition 5.24.0
 */
public final class CPUUsageAsDecoyOutputStream<T extends RandomOutputStream> extends RandomOutputStream {

	public static final double DEFAULT_FALSE_CPU_USAGE_PERCENTAGE=0.05;
	private final T out;
	private AbstractCipher cipher;

	private long CPUTimeUseInNano=0;
	private long falseCPUTimeUseInNano=0;
	private final Random random=new Random(System.nanoTime());
	private final AbstractSecureRandom secureRandom;

	private final SymmetricEncryptionType symmetricEncryptionType;
	private final int opMode;



	public CPUUsageAsDecoyOutputStream(T out) throws IOException {
		this(out, SymmetricEncryptionType.DEFAULT);
	}
	public CPUUsageAsDecoyOutputStream(T out, SymmetricEncryptionType symType) throws IOException {
		if (out==null)
			throw new NullPointerException();
		if (symType==null)
			throw new NullPointerException();
		this.out = out;
		this.symmetricEncryptionType=symType;
		this.opMode=Cipher.ENCRYPT_MODE;
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

	private final byte[] cache=new byte[4];
	void writeFakeBytes(long deltaNano) throws IOException {
		//add false CPU using to fix power side channel attack and frequency side channel attack
		long startTime=System.nanoTime();
		CPUTimeUseInNano+=deltaNano;
		long d=(long)(((double)CPUTimeUseInNano)*(0.75*DEFAULT_FALSE_CPU_USAGE_PERCENTAGE+random.nextDouble()*(DEFAULT_FALSE_CPU_USAGE_PERCENTAGE/2.0)))-falseCPUTimeUseInNano;
		if (d>0) {
			while (d > System.nanoTime() - startTime) {
				Bits.putInt(cache, 0, random.nextInt(32));
				try {
					cipher.update(cache);
				} catch (IOException e) {
					throw new IOException(e);
				}

			}
		}
		falseCPUTimeUseInNano += System.nanoTime() - startTime;
	}

	@Override
	public long length() throws IOException {
		return out.length();
	}

	@Override
	public void write(int b) throws IOException {

		long startNano=System.nanoTime();

		out.write(b);
		if (random.nextInt(CPUUsageAsDecoyOutputStream.MAX_LEN_BEFORE_INJECTING_CPU_USAGE)==0)
		{
			writeFakeBytes(System.nanoTime()-startNano);
		}
		else
			CPUTimeUseInNano+=System.nanoTime()-startNano;

	}
	//static final int MAX_LEN_BEFORE_INJECTING_CPU_USAGE=512*1024;
	static final int MAX_LEN_BEFORE_INJECTING_CPU_USAGE=AbstractEncryptionOutputAlgorithm.BUFFER_SIZE;
	private int computeLen(int len)
	{
		return len<=MAX_LEN_BEFORE_INJECTING_CPU_USAGE?len:MAX_LEN_BEFORE_INJECTING_CPU_USAGE+random.nextInt(len-MAX_LEN_BEFORE_INJECTING_CPU_USAGE+1);
	}

	@Override
	public void write(byte[] b, int off, int len) throws IOException {
		while (len>0) {
			long startNano=System.nanoTime();
			int l = computeLen(len);

			out.write(b, off, l);
			off+=l;
			len-=l;
			writeFakeBytes(System.nanoTime()-startNano);
		}
	}

	@Override
	public void setLength(long newLength) throws IOException {
		out.setLength(newLength);
	}

	@Override
	public void seek(long _pos) throws IOException {
		out.seek(_pos);
	}

	@Override
	public boolean isClosed() {
		return out.isClosed();
	}

	@Override
	protected RandomInputStream getRandomInputStreamImpl() throws IOException {
		return out.getRandomInputStream();
	}

	@Override
	public void flush() throws IOException {
		out.flush();
	}

	@Override
	public void close() throws IOException {
		out.close();
		//cipher.doFinal();
	}

	@Override
	public long currentPosition() throws IOException {
		return out.currentPosition();
	}

	public T getDestinationRandomOutputStream() {
		return out;
	}
}

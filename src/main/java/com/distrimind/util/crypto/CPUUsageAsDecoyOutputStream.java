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
public class CPUUsageAsDecoyOutputStream<T extends RandomOutputStream> extends RandomOutputStream {

	public static final double DEFAULT_FALSE_CPU_USAGE_PERCENTAGE=0.05;
	private final T out;
	private AbstractCipher cipher;

	private long wroteBytes=0;
	private long wroteFakeBytes=0;
	private final Random random=new Random(System.nanoTime());
	private final AbstractSecureRandom secureRandom;
	final static int BUFFER_SIZE = 4096;
	private final byte[] outputBuffer=new byte[BUFFER_SIZE];
	private final byte[] inputBuffer=new byte[BUFFER_SIZE-200];
	private final double falseCPUUsagePercentage=DEFAULT_FALSE_CPU_USAGE_PERCENTAGE;
	private final SymmetricEncryptionType symmetricEncryptionType;
	private final int opMode;



	public CPUUsageAsDecoyOutputStream(T out) throws IOException {
		this(out, SymmetricEncryptionType.DEFAULT, Cipher.ENCRYPT_MODE);
	}
	public CPUUsageAsDecoyOutputStream(T out, SymmetricEncryptionType symType, int opMode) throws IOException {
		if (out==null)
			throw new NullPointerException();
		if (symType==null)
			throw new NullPointerException();
		this.out = out;
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

	private static void writeFakeBytes(AbstractCipher cipher, Random random, long l, byte[] inputBuffer, byte[] outputBuffer) throws IOException {
		if (l>0)
		{
			while (l>0)
			{
				int inputBufferSize=(int)Math.min(inputBuffer.length,l);
				for (int i = 0; i < inputBufferSize; )
					for (int rnd = random.nextInt(),
						 n = Math.min(inputBufferSize - i, Integer.SIZE/Byte.SIZE);
						 n-- > 0; rnd >>= Byte.SIZE)
						inputBuffer[i++] = (byte)rnd;


				/*int s2=cipher.getOutputSize(inputBufferSize);
				if (outputBuffer==null || outputBuffer.length<s2) {
					throw new IOException("outputBuffer.length="+(outputBuffer==null?null:outputBuffer.length)+", s2="+s2+", inputBufferSize="+inputBufferSize);
				}*/
				cipher.update(inputBuffer, 0, inputBufferSize, outputBuffer);
				l-=inputBufferSize;
			}
		}
	}

	@SuppressWarnings("SameParameterValue")
	static long writeFakeBytes(AbstractCipher cipher, AbstractSecureRandom secureRandom, Random random, long length, long wroteFakeBytes, double falseCPUUsagePercentage, byte[] inputBuffer, byte[] outputBuffer, long encodingDurationInNano) throws IOException {
		//add false CPU using to fix power side channel attack and frequency side channel attack
		long startNano=System.nanoTime();
		double delta=secureRandom.nextDouble()*(falseCPUUsagePercentage/2.0)-falseCPUUsagePercentage/4.0;
		final long res=Math.max(0, (long)(((double)length)*(falseCPUUsagePercentage+delta))-wroteFakeBytes);


		if (res>0)
		{
			writeFakeBytes(cipher, random, res, inputBuffer, outputBuffer);
		}
		long deltaNano=System.nanoTime()-startNano;
		double percentageNano=((double)deltaNano)/((double)encodingDurationInNano);
		double percentageWrote=((double)res)/(double)length;
		if (percentageNano<percentageWrote*0.9)
		{
			writeFakeBytes(cipher, random, ((long)(percentageWrote-percentageNano))*res, inputBuffer, outputBuffer);
		}
		return res;
	}

	@Override
	public long length() throws IOException {
		return out.length();
	}

	@Override
	public void write(int b) throws IOException {
		long startNano=System.nanoTime();
		out.write(b);

		wroteFakeBytes+=writeFakeBytes(cipher, secureRandom, random, ++wroteBytes, wroteFakeBytes, falseCPUUsagePercentage,inputBuffer, outputBuffer, System.nanoTime()-startNano);

	}

	@Override
	public void write(byte[] b, int off, int len) throws IOException {
		RandomInputStream.checkLimits(b,off,len);
		while (len>0) {
			int l = len<=AbstractEncryptionOutputAlgorithm.BUFFER_SIZE?secureRandom.nextInt((len/16)+1)*16:secureRandom.nextInt((len/128)+1)*128;
			if (l==0)
				l=len;
			long startNano=System.nanoTime();
			out.write(b, off, l);
			off+=l;
			len-=l;
			wroteBytes+=l;
			wroteFakeBytes+=writeFakeBytes(cipher, secureRandom, random, wroteBytes, wroteFakeBytes, falseCPUUsagePercentage,inputBuffer, outputBuffer, System.nanoTime()-startNano);
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
		cipher.doFinal();
	}

	@Override
	public long currentPosition() throws IOException {
		return out.currentPosition();
	}

	public T getDestinationRandomOutputStream() {
		return out;
	}
}

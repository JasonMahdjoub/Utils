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


import com.distrimind.util.Bits;
import com.distrimind.util.crypto.fortuna.Fortuna;

import java.io.IOException;
import java.io.Serializable;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Arrays;
import java.util.concurrent.ScheduledExecutorService;


/**
 * This class use Fortuna continuously-seeded pseudo-random number generator.
 * This class is thread safe.
 * 
 * @author Jason Mahdjoub
 * @version 2.1
 * @since Utils 2.15
 */
public class FortunaSecureRandom extends AbstractSecureRandom implements Serializable{

	/**
	 * 
	 */
	private static final long serialVersionUID = -51252954999309630L;
	private volatile Object gnuInterface=null;
	private byte[] nonce;
	private byte[] personalizationString;

	private static class SRSpi extends AbstractSecureRandomSpi
	{
		final Fortuna fortuna;
		@SuppressWarnings("unused")
		protected SRSpi(ScheduledExecutorService scheduledExecutorService, SecureRandomType type, byte[] nonce, byte[] personalizationString) throws NoSuchProviderException, NoSuchAlgorithmException {
			super(false);
			if (scheduledExecutorService==null)
				throw new NullPointerException();
			if (type.equals(SecureRandomType.FORTUNA_WITH_BC_FIPS_APPROVED)) {
				fortuna=new Fortuna(scheduledExecutorService,
						SecureRandomType.SHA1PRNG.getSingleton(nonce, personalizationString),
						SecureRandomType.BC_FIPS_APPROVED.getSingleton(nonce, personalizationString));
			}
			else if (type.equals(SecureRandomType.FORTUNA_WITH_BC_FIPS_APPROVED_FOR_KEYS)) {
				fortuna=new Fortuna(scheduledExecutorService,
						SecureRandomType.SHA1PRNG.getSingleton(nonce, personalizationString),
						SecureRandomType.BC_FIPS_APPROVED_FOR_KEYS.getSingleton(nonce, personalizationString));
			}
			else if (type.equals(SecureRandomType.FORTUNA_WITH_BC_FIPS_APPROVED_FOR_KEYS_With_NativePRNG)) {
				fortuna=new Fortuna(scheduledExecutorService,
						SecureRandomType.SHA1PRNG.getSingleton(nonce, personalizationString),
						SecureRandomType.BC_FIPS_APPROVED_FOR_KEYS_With_NativePRNG.getSingleton(nonce, personalizationString));
			}
			else
				throw new IllegalAccessError();
		}
		protected SRSpi(SecureRandomType type, byte[] nonce, byte[] personalizationString) throws NoSuchProviderException, NoSuchAlgorithmException {
			super(false);
			if (type.equals(SecureRandomType.FORTUNA_WITH_BC_FIPS_APPROVED)) {
				fortuna=new Fortuna(
						SecureRandomType.SHA1PRNG.getSingleton(nonce, personalizationString),
						SecureRandomType.BC_FIPS_APPROVED.getSingleton(nonce, personalizationString));
			}
			else if (type.equals(SecureRandomType.FORTUNA_WITH_BC_FIPS_APPROVED_FOR_KEYS)) {
				fortuna=new Fortuna(
						SecureRandomType.SHA1PRNG.getSingleton(nonce, personalizationString),
						SecureRandomType.BC_FIPS_APPROVED_FOR_KEYS.getSingleton(nonce, personalizationString));
			}
			else if (type.equals(SecureRandomType.FORTUNA_WITH_BC_FIPS_APPROVED_FOR_KEYS_With_NativePRNG)) {
				fortuna=new Fortuna(
						SecureRandomType.SHA1PRNG.getSingleton(nonce, personalizationString),
						SecureRandomType.BC_FIPS_APPROVED_FOR_KEYS_With_NativePRNG.getSingleton(nonce, personalizationString));
			}
			else
				throw new IllegalAccessError();
		}

		@Override
		protected void engineSetSeed(byte[] seed) {
			if (seed==null)
				throw new NullPointerException();
			if (seed.length==0)
				throw new IllegalArgumentException();
			if (seed.length<8)
				seed=Arrays.copyOf(seed, 8);
			fortuna.setSeed(Bits.getLong(seed, 0));
		}

		@Override
		protected void engineNextBytes(byte[] bytes) {
			fortuna.nextBytes(bytes);
		}

		@Override
		protected byte[] engineGenerateSeed(int numBytes) {
			byte[] res=new byte[numBytes];
			fortuna.nextBytes(res);
			return res;
		}
	}

	/*FortunaSecureRandom(ScheduledExecutorService scheduledExecutorService, SecureRandomType type) throws NoSuchProviderException, NoSuchAlgorithmException {
		super(new SRSpi(scheduledExecutorService), type);
		checkSources();
	}*/
	FortunaSecureRandom(SecureRandomType type, byte[] nonce, byte[] personalizationString) throws NoSuchProviderException, NoSuchAlgorithmException {
		super(new SRSpi(type, nonce, personalizationString), type);
		this.nonce=nonce;
		this.personalizationString=personalizationString;
	}

	@Override
	public Object getGnuSecureRandom() {
		if (gnuInterface==null)
			gnuInterface=GnuFunctions.getGnuRandomInterface(secureRandomSpi);
		return gnuInterface;
	}

	@Override
	public java.security.SecureRandom getJavaNativeSecureRandom() {
		return this;
	}

	public void addSecureRandomSource(AbstractSecureRandom secureRandom)
	{
		((SRSpi)secureRandomSpi).fortuna.addSecureRandomSource(secureRandom);
	}

	public void addSecureRandomSource(SecureRandomType secureRandomType) throws NoSuchProviderException, NoSuchAlgorithmException {
		((SRSpi)secureRandomSpi).fortuna.addSecureRandomSource(secureRandomType);
	}

	private void writeObject(java.io.ObjectOutputStream out)
			throws IOException
	{
		out.writeInt(getType().ordinal());
		byte[] seed=new byte[32];
		this.nextBytes(seed);
		out.write(seed);
		if (nonce==null) {
			out.writeShort(-1);
		}
		else
		{
			int s = Math.min(nonce.length, 2048);
			out.writeShort(s);
			out.write(nonce, 0, s);
		}
		if (personalizationString==null) {
			out.writeShort(-1);
		}
		else
		{
			int s = Math.min(personalizationString.length, 2048);
			out.writeShort(s);
			out.write(personalizationString, 0, s);
		}


	}
	private void readObject(java.io.ObjectInputStream in)
			throws IOException, ClassNotFoundException
	{

		super.type=null;
		int code=in.readInt();
		for (SecureRandomType srt : SecureRandomType.values()) {
			if (srt.ordinal()==code) {
				super.type = srt;
				break;
			}
		}
		if (super.type==null)
			super.type=SecureRandomType.FORTUNA_WITH_BC_FIPS_APPROVED_FOR_KEYS;

		byte[] seed=new byte[32];
		in.readFully(seed);
		setSeed(seed);
		int s=in.readShort();
		if (s<=0)
			nonce=null;
		else
		{
			if (s>2048)
				throw new IOException();
			nonce=new byte[s];
			in.readFully(nonce);
		}
		s=in.readShort();
		if (s<=0)
			personalizationString=null;
		else
		{
			if (s>2048)
				throw new IOException();
			personalizationString=new byte[s];
			in.readFully(personalizationString);
		}
		try {
			super.secureRandomSpi=new SRSpi(type, nonce, personalizationString);
		} catch (NoSuchProviderException | NoSuchAlgorithmException e) {
			throw new IOException(e);
		}

	}

}

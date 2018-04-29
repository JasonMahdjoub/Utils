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

import java.io.Serializable;
import java.util.Collections;
import java.util.Map;

import gnu.jgnu.security.hash.IMessageDigest;
import gnu.jgnu.security.prng.IRandom;
import gnu.jgnu.security.prng.LimitReachedException;
import gnu.jgnu.security.prng.RandomEvent;
import gnu.jgnu.security.prng.RandomEventListener;
import gnu.jgnux.crypto.prng.Fortuna;
import gnu.vm.jgnu.security.NoSuchAlgorithmException;
import gnu.vm.jgnu.security.NoSuchProviderException;
import gnu.vm.jgnu.security.SecureRandom;

/**
 * This class use Fortuna continuously-seeded pseudo-random number generator.
 * This class is thread safe.
 * 
 * @author Jason Mahdjoub
 * @version 1.1
 * @since Utils 2.15
 */
public class FortunaSecureRandom extends AbstractSecureRandom implements Serializable, IRandom, RandomEventListener{

	/**
	 * 
	 */
	private static final long serialVersionUID = -512529549993096330L;
	
	
	//private transient final SecureRandomType types[];
	private transient final GnuInterface secureGnuRandom;
	
	private static final short initialGeneratedSeedSize=64;
	
	private boolean initialized;
	public FortunaSecureRandom(byte nonce[]) throws NoSuchAlgorithmException, NoSuchProviderException {
		this(nonce, null);
	}
	public FortunaSecureRandom(byte nonce[], byte [] personalizationString) throws NoSuchAlgorithmException, NoSuchProviderException {
		this(nonce, personalizationString, SecureRandomType.SHA1PRNG, SecureRandomType.GNU_SHA512PRNG);
	}
	
	private static class RandomSpi extends AbstractSecureRandomSpi
	{
		/**
		 * 
		 */
		private static final long serialVersionUID = -8786132962158601823L;
		
		private volatile FortunaImpl fortuna=null;
		private transient boolean fortunaInitialized=false;
		private transient final AbstractSecureRandom randoms[];
		protected final byte nonce[], personalizationString[];

		protected RandomSpi(byte nonce[], byte [] personalizationString, SecureRandomType ... types) throws NoSuchAlgorithmException, NoSuchProviderException
		{
			super(false);
			this.nonce=nonce;
			this.personalizationString=personalizationString;
			fortuna=null;
			if (types.length==0)
				throw new IllegalArgumentException();
			randoms=new AbstractSecureRandom[types.length];
			for (int i=0;i<randoms.length;i++)
				randoms[i]=types[i].getInstance(nonce, personalizationString);
			
		}
		
		
		private FortunaImpl getFortunaInstance()
		{
			if (fortuna==null)
			{
				synchronized(this)
				{
					if (fortuna==null)
					{
						fortuna=new FortunaImpl();
					}
				}
			}
			if (!fortunaInitialized)
			{
				synchronized(this)
				{
					if (!fortunaInitialized)
					{
						fortuna.init(Collections.singletonMap((Object)Fortuna.SEED, engineGenerateSeed(initialGeneratedSeedSize)));
						fortunaInitialized=true;
					}
				}
			}
			return fortuna;
		}

		@Override
		protected void engineSetSeed(byte[] seed) {
			if (seed==null)
				throw new NullPointerException();
			if (seed.length==0)
				throw new IllegalArgumentException();
			synchronized(this)
			{
				getFortunaInstance().setup(Collections.singletonMap((Object)Fortuna.SEED, seed));
			}			
		}

		@Override
		protected void engineNextBytes(byte[] bytes) {
			synchronized(this)
			{
				try
				{
					getFortunaInstance().nextBytes(bytes);
				}
				catch(Exception e)
				{
					e.printStackTrace();
					throw new IllegalAccessError();
				}
			}
			
		}

		@Override
		protected byte[] engineGenerateSeed(int numBytes) {
			synchronized(this)
			{
				byte[] seed;
				try {
					seed = SecureRandomType.tryToGenerateNativeNonBlockingSeed(numBytes);
				} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
					e.printStackTrace();
					seed=new byte[numBytes];
				}
				byte[] s=null;
				for (int i=0;i<randoms.length;i++)
				{
					if (s==null)
						s=new byte[numBytes];
					randoms[i].nextBytes(s);
					for (int j=0;j<numBytes;j++)
						seed[j]=(byte)(seed[i]^s[i]);
				}
				return seed;
			}
		}
		
		protected class FortunaImpl extends Fortuna
		{
			private static final long serialVersionUID =2335;
			@Override
			protected void refreshDigestWithRandomEvents(IMessageDigest pool)
			{
				for (int i=0;i<randoms.length;i++)
				{
					byte[] tab=new byte[20];
					randoms[i].nextBytes(tab);
					pool.update(tab);				
				}
				try {
					pool.update(SecureRandomType.tryToGenerateNativeNonBlockingRandomBytes(20));
				} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
					e.printStackTrace();
				}
			}

			@Override public FortunaImpl clone() throws CloneNotSupportedException
			{
				return (FortunaImpl) super.clone();
			}
		}
		
	}
	
	FortunaSecureRandom(byte nonce[], byte [] personalizationString, SecureRandomType ... types) throws NoSuchAlgorithmException, NoSuchProviderException {
		super(new RandomSpi(nonce, personalizationString, types),null);
		
		initialized=false;
		secureGnuRandom=new GnuInterface();
		initialized=true;
	}

	@Override
	public FortunaSecureRandom clone() throws CloneNotSupportedException
	{
		try
		{
			RandomSpi rs=((FortunaSecureRandom.RandomSpi)this.secureRandomSpi);
			FortunaSecureRandom res=new FortunaSecureRandom(rs.nonce, rs.personalizationString);
			((FortunaSecureRandom.RandomSpi)res.secureRandomSpi).fortuna=rs.getFortunaInstance().clone();
			return res;
		}
		catch(Exception e)
		{
			throw new CloneNotSupportedException(e.toString());
		}
	}

	@Override
	public SecureRandom getGnuSecureRandom() {
		return secureGnuRandom;
	}

	@Override
	public java.security.SecureRandom getJavaNativeSecureRandom() {
		return this;
	}
	
	public void setSeedAndNextBytes(byte[] seed, byte[] bytes)
	{
		synchronized(this)
		{
			this.setSeed(seed);
			this.nextBytes(bytes);
		}
	}

	
	@Override
	public void addRandomByte(byte arg0) {
		synchronized(this)
		{
			((FortunaSecureRandom.RandomSpi)this.secureRandomSpi).getFortunaInstance().addRandomByte(arg0);
		}
		
	}

	@Override
	public void addRandomBytes(byte[] arg0) {
		synchronized(this)
		{
			((FortunaSecureRandom.RandomSpi)this.secureRandomSpi).getFortunaInstance().addRandomBytes(arg0);
		}
		
	}

	@Override
	public void addRandomBytes(byte[] arg0, int arg1, int arg2) {
		synchronized(this)
		{
			((FortunaSecureRandom.RandomSpi)this.secureRandomSpi).getFortunaInstance().addRandomBytes(arg0, arg1, arg2);
		}
	}

	@Override
	public void init(Map<Object, ?> arg0) {
		synchronized(this)
		{
			((FortunaSecureRandom.RandomSpi)this.secureRandomSpi).getFortunaInstance().init(arg0);
		}
		
	}

	@Override
	public String name() {
		synchronized(this)
		{
			return ((FortunaSecureRandom.RandomSpi)this.secureRandomSpi).getFortunaInstance().name();
		}
	}

	@Override
	public byte nextByte() throws IllegalStateException, LimitReachedException {
		synchronized(this)
		{
			return ((FortunaSecureRandom.RandomSpi)this.secureRandomSpi).getFortunaInstance().nextByte();
		}
	}

	@Override
	public void nextBytes(byte[] arg0, int arg1, int arg2) throws IllegalStateException, LimitReachedException {
		synchronized(this)
		{
			((FortunaSecureRandom.RandomSpi)this.secureRandomSpi).getFortunaInstance().nextBytes(arg0, arg1, arg2);
		}
				
	}
	@Override
	public void addRandomEvent(RandomEvent arg0) {
		synchronized(this)
		{
			((FortunaSecureRandom.RandomSpi)this.secureRandomSpi).getFortunaInstance().addRandomEvent(arg0);
		}
		
	}
	
	
	
	private class GnuInterface extends SecureRandom {
		/**
		 * 
		 */
		private static final long serialVersionUID = 4299616485652308411L;

		
		protected GnuInterface() {
			super(new gnu.vm.jgnu.security.SecureRandomSpi() {
				
				
				/**
				 * 
				 */
				private static final long serialVersionUID = 740095511171490031L;

				@Override
				protected void engineSetSeed(byte[] seed) {
					if (initialized)
						FortunaSecureRandom.this.secureRandomSpi.engineSetSeed(seed);
				}
				
				@Override
				protected void engineNextBytes(byte[] bytes) {
					if (initialized)
						FortunaSecureRandom.this.secureRandomSpi.engineNextBytes(bytes);
					
				}
				
				@Override
				protected byte[] engineGenerateSeed(int numBytes) {
					return FortunaSecureRandom.this.secureRandomSpi.engineGenerateSeed(numBytes);
				}
			}, null);
			
		}
	}
	


}

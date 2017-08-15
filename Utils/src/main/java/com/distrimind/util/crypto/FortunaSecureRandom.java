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

import com.distrimind.util.Bits;

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
 * @version 1.0
 * @since Utils 2.15
 */
public class FortunaSecureRandom extends AbstractSecureRandom implements Serializable, IRandom, RandomEventListener{

	/**
	 * 
	 */
	private static final long serialVersionUID = -512529549993096330L;
	
	private volatile FortunaImpl fortuna;
	private transient final AbstractSecureRandom randomStrong,randomSHA1PRNG, randomGNU_SHA512PRNG;
	private transient final GnuInterface secureGnuRandom;
	private transient final JavaNativeInterface secureJavaNativeRandom;
	private transient boolean fortunaInitialized=false;
	private static final short initialGeneratedSeedSize=64;
	
	public FortunaSecureRandom() throws NoSuchAlgorithmException, NoSuchProviderException {
		super(SecureRandomType.GNU_FORTUNA, false);
		fortuna=null;
		randomStrong=SecureRandomType.NativePRNGBlocking.getInstance();
		randomSHA1PRNG=SecureRandomType.SHA1PRNG.getInstance();
		randomGNU_SHA512PRNG=SecureRandomType.GNU_SHA512PRNG.getInstance();
		secureGnuRandom=new GnuInterface();
		secureJavaNativeRandom=new JavaNativeInterface();
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
					fortuna.init(Collections.singletonMap((Object)Fortuna.SEED, generateSeed(initialGeneratedSeedSize)));
					fortunaInitialized=true;
				}
			}
		}
		return fortuna;
	}
	@Override
	public FortunaSecureRandom clone() throws CloneNotSupportedException
	{
		try
		{
			FortunaSecureRandom res=new FortunaSecureRandom();
			res.fortuna=getFortunaInstance().clone();
			return res;
		}
		catch(Exception e)
		{
			throw new CloneNotSupportedException(e.toString());
		}
	}
	
	@Override
	public byte[] generateSeed(int numBytes) {
		synchronized(this)
		{
			byte[] seedStrong=new byte[numBytes];
			randomStrong.nextBytes(seedStrong);
			byte[] seedSHA1PRNG=new byte[numBytes];
			randomSHA1PRNG.nextBytes(seedSHA1PRNG);
			byte[] seedGNU_SHA512PRNG=new byte[numBytes];
			randomGNU_SHA512PRNG.nextBytes(seedGNU_SHA512PRNG);
			byte[] seed=new byte[numBytes];
			for (int i=0;i<numBytes;i++)
				seed[i]=(byte)(seedStrong[i]^seedSHA1PRNG[i]^seedGNU_SHA512PRNG[i]);
			return seed;
		}
	}

	@Override
	public String getAlgorithm() {
		return getType().name();
	}

	@Override
	public SecureRandom getGnuSecureRandom() {
		return secureGnuRandom;
	}

	@Override
	public java.security.SecureRandom getJavaNativeSecureRandom() {
		return secureJavaNativeRandom;
	}

	@Override
	public void nextBytes(byte[] bytes){
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
	
	public void setSeedAndNextBytes(byte[] seed, byte[] bytes)
	{
		synchronized(this)
		{
			this.setSeed(seed);
			this.nextBytes(bytes);
		}
	}

	@Override
	public void setSeed(byte[] seed) {
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
	public void setSeed(long seed) {
		
		if (randomStrong!=null)
		{
			byte[] s=new byte[8];
			Bits.putLong(s, 0, seed);
			setSeed(s);
		}
	}
	
	@Override
	public void addRandomByte(byte arg0) {
		synchronized(this)
		{
			getFortunaInstance().addRandomByte(arg0);
		}
		
	}

	@Override
	public void addRandomBytes(byte[] arg0) {
		synchronized(this)
		{
			getFortunaInstance().addRandomBytes(arg0);
		}
		
	}

	@Override
	public void addRandomBytes(byte[] arg0, int arg1, int arg2) {
		synchronized(this)
		{
			getFortunaInstance().addRandomBytes(arg0, arg1, arg2);
		}
	}

	@Override
	public void init(Map<Object, ?> arg0) {
		synchronized(this)
		{
			getFortunaInstance().init(arg0);
		}
		
	}

	@Override
	public String name() {
		synchronized(this)
		{
			return getFortunaInstance().name();
		}
	}

	@Override
	public byte nextByte() throws IllegalStateException, LimitReachedException {
		synchronized(this)
		{
			return getFortunaInstance().nextByte();
		}
	}

	@Override
	public void nextBytes(byte[] arg0, int arg1, int arg2) throws IllegalStateException, LimitReachedException {
		synchronized(this)
		{
			getFortunaInstance().nextBytes(arg0, arg1, arg2);
		}
				
	}
	@Override
	public void addRandomEvent(RandomEvent arg0) {
		synchronized(this)
		{
			getFortunaInstance().addRandomEvent(arg0);
		}
		
	}
	
	
	
	private class GnuInterface extends SecureRandom {
		/**
		 * 
		 */
		private static final long serialVersionUID = 4299616485652308411L;

		protected GnuInterface() {
			super(null, null);
			
		}

		@Override
		public byte[] generateSeed(int _numBytes) {
			return FortunaSecureRandom.this.generateSeed(_numBytes);
		}

		@Override
		public String getAlgorithm() {
			return FortunaSecureRandom.this.getAlgorithm();
		}

		@Override
		public void nextBytes(byte[] _bytes) {
			FortunaSecureRandom.this.nextBytes(_bytes);
		}

		@Override
		public void setSeed(byte[] _seed) {
			FortunaSecureRandom.this.setSeed(_seed);
		}

		@Override
		public void setSeed(long _seed) {
			FortunaSecureRandom.this.setSeed(_seed);

		}

	}
	private class JavaNativeInterface extends java.security.SecureRandom {
		/**
		 * 
		 */
		private static final long serialVersionUID = 4299616485652308411L;

		protected JavaNativeInterface() {
			super(null, null);
			
		}

		@Override
		public byte[] generateSeed(int _numBytes) {
			return FortunaSecureRandom.this.generateSeed(_numBytes);
		}

		@Override
		public String getAlgorithm() {
			return FortunaSecureRandom.this.getAlgorithm();
		}

		@Override
		public void nextBytes(byte[] _bytes) {
			FortunaSecureRandom.this.nextBytes(_bytes);
		}

		@Override
		public void setSeed(byte[] _seed) {
			FortunaSecureRandom.this.setSeed(_seed);
		}

		@Override
		public void setSeed(long _seed) {
			FortunaSecureRandom.this.setSeed(_seed);

		}

	}
	
	private class FortunaImpl extends Fortuna
	{
		@Override
		protected void refreshDigestWithRandomEvents(IMessageDigest pool)
		{
			byte[] tab=new byte[8];
			randomStrong.nextBytes(tab);
			pool.update(tab);
			
			tab=new byte[32];
			randomSHA1PRNG.nextBytes(tab);
			pool.update(tab);

			tab=new byte[64];
			randomGNU_SHA512PRNG.nextBytes(tab);
			pool.update(tab);
		}

		@Override public FortunaImpl clone() throws CloneNotSupportedException
		{
			return (FortunaImpl) super.clone();
		}
	}



}

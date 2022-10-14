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

import com.distrimind.bcfips.crypto.EntropySourceProvider;
import com.distrimind.bcfips.crypto.fips.FipsDRBG;
import com.distrimind.bcfips.crypto.util.BasicEntropySourceProvider;
import com.distrimind.util.OS;
import com.distrimind.util.OSVersion;
import com.distrimind.util.io.RandomFileInputStream;

import java.io.File;
import java.io.IOException;
import java.net.NetworkInterface;
import java.security.*;
import java.util.*;

/**
 * 
 * @author Jason Mahdjoub
 * @version 3.0.0
 * @since Utils 2.0
 */
@SuppressWarnings("DeprecatedIsStillUsed")
public enum SecureRandomType {
	SHA1PRNG("SHA1PRNG", CodeProvider.SUN, false, true),
	@Deprecated
	GNU_SHA1PRNG("SHA1PRNG", CodeProvider.GNU_CRYPTO, true, true),
	@Deprecated
	GNU_SHA256PRNG("SHA-256PRNG", CodeProvider.GNU_CRYPTO, true, true),
	@Deprecated
	GNU_SHA384PRNG("SHA-384PRNG", CodeProvider.GNU_CRYPTO, true, true), 
	GNU_SHA512PRNG("SHA-512PRNG",CodeProvider.GNU_CRYPTO, true, true),
	@Deprecated
	GNU_WIRLPOOLPRNG("WHIRLPOOLPRNG", CodeProvider.GNU_CRYPTO, true, true),
	@Deprecated
	GNU_DEFAULT(GNU_SHA1PRNG),
	SPEEDIEST(GNU_SHA512PRNG), 
	NativePRNG("NativePRNG", CodeProvider.SUN, false, false),
	NativePRNGNonBlocking("NativePRNGNonBlocking", CodeProvider.SUN, false, false),
	JAVA_STRONG_DRBG("JAVA_STRONG_DRBG", CodeProvider.SUN, false, true),
	BC_FIPS_APPROVED("BC_FIPS_APPROVED", CodeProvider.BCFIPS, false, false),
	BC_FIPS_APPROVED_FOR_KEYS("BC_FIPS_APPROVED_FOR_KEYS", CodeProvider.BCFIPS, false, false),
	BC_FIPS_APPROVED_FOR_KEYS_With_NATIVE_PRNG("BC_FIPS_APPROVED_FOR_KEYS_With_NativePRNG", CodeProvider.BCFIPS, false, false),
	DEFAULT_BC_FIPS_APPROVED("DEFAULT_BC_FIPS_APPROVED", CodeProvider.BCFIPS, false, false),
	FORTUNA_WITH_BC_FIPS_APPROVED("FORTUNA_WITH_BC_FIPS_APPROVED", CodeProvider.BC, false, false),
	FORTUNA_WITH_BC_FIPS_APPROVED_FOR_KEYS("FORTUNA_WITH_BC_FIPS_APPROVED_FOR_KEYS", CodeProvider.BC, false, true),
	FORTUNA_WITH_BC_FIPS_APPROVED_FOR_KEYS_With_NativePRNG("FORTUNA_WITH_BC_FIPS_APPROVED_FOR_KEYS_With_NativePRNG", CodeProvider.BC, false, true),
	DEFAULT(BC_FIPS_APPROVED);

	private final String algorithmName;

	private final CodeProvider provider;

	private final boolean gnuVersion;
	
	private final boolean needInitialSeed;
	
	private static final Map<SecureRandomType, AbstractSecureRandom> singletons=Collections.synchronizedMap(new HashMap<>());
	private SecureRandomType derivedType;

	public boolean equals(SecureRandomType type)
	{
		if (type==null)
			return false;
		//noinspection StringEquality
		return this.algorithmName ==type.algorithmName && this.provider==type.provider;
	}

	SecureRandomType(SecureRandomType type) {
		this(type.algorithmName, type.provider, type.gnuVersion, type.needInitialSeed);
		this.derivedType=type;
	}
	
	boolean needInitialSeed()
	{
		return needInitialSeed;
	}

	SecureRandomType(String algorithmName, CodeProvider provider, boolean gnuVersion, boolean needInitialSeed) {
		this.algorithmName = algorithmName;
		this.provider = provider;
		this.gnuVersion = gnuVersion;
		this.needInitialSeed=needInitialSeed;
		this.derivedType=this;
	}
	
	public String getAlgorithmName()
	{
		return algorithmName;
	}
	
	/**
	 * 
	 * @param nonce               value to use in DRBG construction.
	 * @return the secure random
	 * @throws NoSuchAlgorithmException if the algorithm was not found
	 * @throws NoSuchProviderException if the provider was not found
	 */
	public AbstractSecureRandom getInstance(byte[] nonce) throws NoSuchAlgorithmException, NoSuchProviderException
	{
		return getInstance(nonce, (byte[])null);
	}
	
	/**
	 * 
	 * @param nonce               value to use in DRBG construction.
	 * @param personalizationString the personalization string
	 * @return the secure random
	 * @throws NoSuchAlgorithmException if the algorithm was not found
	 * @throws NoSuchProviderException if the provider was not found
	 */
	public AbstractSecureRandom getInstance(byte[] nonce, String personalizationString) throws NoSuchAlgorithmException, NoSuchProviderException
	{
		return getInstance(nonce, personalizationString==null?null:personalizationString.getBytes());
	}

	public static void main(String[] args) throws NoSuchProviderException, NoSuchAlgorithmException {
		System.out.println("Test native");
		SecureRandomType.NativePRNGNonBlocking.getSingleton(null).nextBytes(new byte[262144]);
		System.out.println("Test BC_FIPS APPROVED");
		SecureRandomType.BC_FIPS_APPROVED.getSingleton(null).nextBytes(new byte[262144/8]);
		System.out.println("Test FORTUNA");
		SecureRandomType.FORTUNA_WITH_BC_FIPS_APPROVED.getSingleton(null).nextBytes(new byte[262144/8]);
	}

	/**
	 * 
	 * @param nonce               value to use in DRBG construction.
	 * @param personalizationString the personalisation string for the underlying DRBG.
	 * @return the secure random
	 * @throws NoSuchAlgorithmException if the algorithm was not found
	 * @throws NoSuchProviderException if the provider was not found
	 */
	public AbstractSecureRandom getInstance(byte[] nonce, byte[] personalizationString)
			throws NoSuchAlgorithmException, NoSuchProviderException {
		//CodeProvider.ensureProviderLoaded(provider);
		AbstractSecureRandom res;
		if (gnuVersion) {
			if (algorithmName == null)
				res=new GnuSecureRandom(this, GnuFunctions.secureRandomGetInstance());
			else
				res=new GnuSecureRandom(this, GnuFunctions.secureRandomGetInstance(algorithmName));
		} else {
			if (nonce==null)
			{
				nonce=SecureRandomType.nonce;
			}
			if (BC_FIPS_APPROVED.algorithmName.equals(this.algorithmName) || BC_FIPS_APPROVED_FOR_KEYS.algorithmName.equals(this.algorithmName) || BC_FIPS_APPROVED_FOR_KEYS_With_NATIVE_PRNG.algorithmName.equals(this.algorithmName))
			{

				SecureRandom srSource= BC_FIPS_APPROVED_FOR_KEYS_With_NATIVE_PRNG.algorithmName.equals(this.algorithmName)?SecureRandomType.NativePRNG.getSingleton(null):SecureRandomType.JAVA_STRONG_DRBG.getSingleton(null);

				EntropySourceProvider entSource = new BasicEntropySourceProvider(srSource, true);
				FipsDRBG.Builder drgbBldr = FipsDRBG.SHA512_HMAC.fromEntropySource(entSource)
						.setSecurityStrength(256)
						.setEntropyBitsRequired(256);
				
				if (personalizationString!=null)
				{
					drgbBldr=drgbBldr.setPersonalizationString(personalizationString);
				}
				res=new JavaNativeSecureRandom(this, drgbBldr.build(nonce,BC_FIPS_APPROVED_FOR_KEYS.algorithmName.equals(this.algorithmName) || BC_FIPS_APPROVED_FOR_KEYS_With_NATIVE_PRNG.algorithmName.equals(this.algorithmName)), false);
				return res;
			}
			else if (DEFAULT_BC_FIPS_APPROVED.equals(this))
			{
				SecureRandom srSource=SecureRandomType.JAVA_STRONG_DRBG.getSingleton(null);


				EntropySourceProvider entSource = new BasicEntropySourceProvider(srSource, true);
				FipsDRBG.Builder drgbBldr = FipsDRBG.SHA512.fromEntropySource(entSource)
						.setSecurityStrength(256)
						.setEntropyBitsRequired(256);
				if (personalizationString!=null)
				{
					drgbBldr=drgbBldr.setPersonalizationString(personalizationString);
				}
				return new JavaNativeSecureRandom(this, drgbBldr.build(nonce,true), false);
			}
			else if (algorithmName.startsWith("FORTUNA")) {
				return new FortunaSecureRandom(this, nonce, personalizationString);
			}
			else if (NativePRNGNonBlocking.algorithmName.equals(algorithmName))
			{
				return new NativeNonBlockingSecureRandom();
			}
			else if (JAVA_STRONG_DRBG.algorithmName.equals(algorithmName))
			{
				if (OSVersion.getCurrentOSVersion().getOS()==OS.ANDROID)
					res=new JavaNativeSecureRandom(this,new SecureRandom());
				else
					res=new JavaNativeSecureRandom(this, SecureRandom.getInstanceStrong());
			}
			else
			{
				if (OSVersion.getCurrentOSVersion().getOS()==OS.ANDROID)
					res=new JavaNativeSecureRandom(this, new SecureRandom());
				else
					res=new JavaNativeSecureRandom(this, SecureRandom.getInstance(algorithmName, provider.getCompatibleProvider()));
			}
		}
		if (nonce!=null) {

			res.setSeed(nonce);
		}
		return res;

	}
	

	public AbstractSecureRandom getInstance(long seed)
			throws NoSuchAlgorithmException, NoSuchProviderException {
		byte[] nonce=SecureRandomType.nonce.clone();
		nonce[0] ^= (byte) (seed >>> 56);
		nonce[1] ^= (byte) (seed >>> 48);
		nonce[2] ^= (byte) (seed >>> 40);
		nonce[3] ^= (byte) (seed >>> 32);
		nonce[4] ^= (byte) (seed >>> 24);
		nonce[5] ^= (byte) (seed >>> 16);
		nonce[6] ^= (byte) (seed >>> 8);
		nonce[7] ^= (byte) (seed);
		return getInstance(nonce);
	}

	public boolean isGNUVersion() {
		return gnuVersion;
	}
	
	public CodeProvider getProvider()
	{
		return provider;
	}
	
	
	final static byte[] nonce;
	
	static
	{
		long result = 0;
		long result2=0;
		try {
			final Enumeration<NetworkInterface> e = NetworkInterface.getNetworkInterfaces();
			while (e.hasMoreElements()) {
				final NetworkInterface ni = e.nextElement();

				if (!ni.isLoopback()) {

					long val = getHardwareAddress(ni.getHardwareAddress());
					if (val != 0 && val != 224)
					{
						if (ni.isPointToPoint()) {
							result2=val;
						}
						else {
							result = val;
							break;
						}
					}
				}
			}
		}
		catch(Exception e)
		{
			e.printStackTrace();
		}
		if (result==0)
			result=result2;
		//noinspection SpellCheckingInspection
		nonce=("La "+result+"piethagore\n" +
				"dans le ciel bleu\n" + 
				"décrit des figures\n" + 
				"géométriques.\n" + 
				"Acrobate émérite,\n" + 
				"elle dessine en son vol\n" + 
				"moult ellipses et paraboles.\n" + 
				"D’ailleurs, pour être précis,\n" + 
				"le carré de son aile vaut\n" + 
				"la somme des carrés de ses petites pattes.\n" + 
				"La piethagore est maternelle :\n" + 
				"dans le tore du nid elle couve\n" + 
				"ses œufs parfaitement sphériques,\n" + 
				"à côté d’un compas en or\n" + 
				"dérobé à la Castafiore.").getBytes();
	}
	
	private static long getHardwareAddress(byte[] hardwareAddress) {
		long result = 0;
		if (hardwareAddress != null) {
			for (final byte value : hardwareAddress) {
				result <<= 8;
				result |= value & 255;
			}
		}
		return result;
	}
	
	
	
	public AbstractSecureRandom getSingleton(byte[] nonce) throws NoSuchAlgorithmException, NoSuchProviderException
	{
		return getSingleton(nonce, null);
	}
	public AbstractSecureRandom getSingleton(byte[] nonce, byte[] personalizationString) throws NoSuchAlgorithmException, NoSuchProviderException
	{
		return getSingleton(nonce, personalizationString, false);
	}
	public AbstractSecureRandom getSingleton(byte[] nonce, byte[] personalizationString, boolean regenerate) throws NoSuchAlgorithmException, NoSuchProviderException
	{
		AbstractSecureRandom res=null;
		if (!regenerate)
			res=singletons.get(this);
		if (res==null)
		{
			synchronized(singletons)
			{
				if (!regenerate)
					res=singletons.get(this);
				if (res==null)
				{
					res=this.getInstance(nonce, personalizationString);
					singletons.put(this, res);
				}
			}
		}
		return res;
	}
	
	static private File getURandomPath()
	{
		return new File("/dev/urandom");
	}
	
	private static volatile SecureRandom defaultNativeNonBlockingSeed=null;
	static SecureRandom getDefaultNativeNonBlockingSeedSingleton()
	{
		if (defaultNativeNonBlockingSeed==null)
		{
			synchronized(NativeNonBlockingSecureRandom.class)
			{
				if (defaultNativeNonBlockingSeed==null)
				{
					SecureRandom sr=null;
					if (OSVersion.getCurrentOSVersion()!=null && OSVersion.getCurrentOSVersion().getOS().isUnix())
					{
						try {
							if (OSVersion.getCurrentOSVersion().getOS()==OS.ANDROID)
								sr=new SecureRandom();
							else
								sr=SecureRandom.getInstance("NativePRNG", CodeProvider.SUN.getCompatibleProvider());
						} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
							try
							{
								sr=SecureRandom.getInstance("SHA1PRNG", CodeProvider.SUN.getCompatibleProvider());
							}
							catch(NoSuchAlgorithmException | NoSuchProviderException e2)
							{
								e2.printStackTrace();
								System.exit(-1);
							}
						}
					}
					else
					{
						try
						{
							if (Objects.requireNonNull(OSVersion.getCurrentOSVersion()).getOS()==OS.ANDROID)
								sr=new SecureRandom();
							else
								sr=SecureRandom.getInstance("SHA1PRNG", CodeProvider.SUN.getCompatibleProvider());
						}
						catch(NoSuchAlgorithmException | NoSuchProviderException e2)
						{
							e2.printStackTrace();
							System.exit(-1);
						}
					}
					
					defaultNativeNonBlockingSeed=sr;
				}
			}
		}
		return defaultNativeNonBlockingSeed;
	}

	private static volatile JavaNativeSecureRandom nativeNonBlockingSeed=null;
	private static volatile boolean nativeNonBlockingSeedInitialized=false;
	
	public static void tryToGenerateNativeNonBlockingRandomBytes(final byte[] buffer)
	{
		if (OS.getCurrentJREVersionDouble()>=1.8)
		{
			if (!nativeNonBlockingSeedInitialized)
			{
				synchronized(NativeNonBlockingSecureRandom.class)
				{
					if (!nativeNonBlockingSeedInitialized)
					{
						nativeNonBlockingSeedInitialized=true;
						try {
							nativeNonBlockingSeed=new JavaNativeSecureRandom(NativePRNGNonBlocking, SecureRandom.getInstance("NativePRNGNonBlocking", CodeProvider.SUN.getCompatibleProvider()), false);
						} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
							nativeNonBlockingSeed=null;
						}
					}
				}
			}
			if (nativeNonBlockingSeed!=null)
			{
				nativeNonBlockingSeed.nextBytes(buffer);
            }
		}
		else if (OSVersion.getCurrentOSVersion()!=null && OSVersion.getCurrentOSVersion().getOS().isUnix())
		{
			
			AccessController.doPrivileged((PrivilegedAction<Void>) () -> {
					synchronized(NativeNonBlockingSecureRandom.class)
					{
						File randomSource=getURandomPath();

						try (RandomFileInputStream in = new RandomFileInputStream(randomSource)) {
							in.readFully(buffer);
							return null;
						}
						catch(IOException e)
						{
							e.printStackTrace();
						}
						getDefaultNativeNonBlockingSeedSingleton().nextBytes(buffer);
					}

				return null;
			});

		}
		else
		{
			synchronized(NativeNonBlockingSecureRandom.class)
			{
				getDefaultNativeNonBlockingSeedSingleton().nextBytes(buffer);
			}
		}
	}
	public static byte[] tryToGenerateNativeNonBlockingSeed(final int numBytes)
	{
		if (OSVersion.getCurrentOSVersion()!=null && OSVersion.getCurrentOSVersion().getOS().isUnix())
		{
			if (OSVersion.getCurrentOSVersion().getOS()==OS.ANDROID)
			{
				if (!nativeNonBlockingSeedInitialized) {
					synchronized (NativeNonBlockingSecureRandom.class) {
						if (!nativeNonBlockingSeedInitialized) {
							nativeNonBlockingSeed = new JavaNativeSecureRandom(NativePRNGNonBlocking, new SecureRandom(), false);
							nativeNonBlockingSeedInitialized = true;
						}
					}
				}
				if (nativeNonBlockingSeed!=null)
				{
					return nativeNonBlockingSeed.generateSeed(numBytes);
				}
			}
			else if (OS.getCurrentJREVersionDouble()>=1.8)
			{
				if (!nativeNonBlockingSeedInitialized)
				{
					synchronized(NativeNonBlockingSecureRandom.class)
					{
						if (!nativeNonBlockingSeedInitialized)
						{
							try {
								nativeNonBlockingSeed=new JavaNativeSecureRandom(NativePRNGNonBlocking, SecureRandom.getInstance("NativePRNGNonBlocking", CodeProvider.SUN.getCompatibleProvider()), false);
							} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
								nativeNonBlockingSeed=null;
							}
							nativeNonBlockingSeedInitialized=true;
						}
					}
				}
				if (nativeNonBlockingSeed!=null)
				{
					return nativeNonBlockingSeed.generateSeed(numBytes);
				}
			}
				
			return AccessController.doPrivileged((PrivilegedAction<byte[]>) () -> {
				synchronized (NativeNonBlockingSecureRandom.class) {
					File randomSource = getURandomPath();

					try (RandomFileInputStream in = new RandomFileInputStream(randomSource)) {
						byte[] buffer = new byte[numBytes];
						in.readFully(buffer);
						return buffer;
					} catch (IOException e) {
						e.printStackTrace();
					}
					return getDefaultNativeNonBlockingSeedSingleton().generateSeed(numBytes);
				}
			});

		}
		else
		{
			synchronized(NativeNonBlockingSecureRandom.class)
			{
				return getDefaultNativeNonBlockingSeedSingleton().generateSeed(numBytes);
			}
		}
	}

	public SecureRandomType getDerivedType() {
		return derivedType;
	}
}

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

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.EntropySourceProvider;
import org.bouncycastle.crypto.fips.FipsDRBG;
import org.bouncycastle.crypto.util.BasicEntropySourceProvider;

import com.distrimind.util.Bits;

/**
 * 
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 2.0
 */
public enum SecureRandomType {
	SHA1PRNG("SHA1PRNG", CodeProvider.SUN, false, true), 
	GNU_SHA1PRNG("SHA1PRNG", CodeProvider.GNU_CRYPTO, true, true), 
	GNU_SHA256PRNG("SHA-256PRNG", CodeProvider.GNU_CRYPTO, true, true), 
	GNU_SHA384PRNG("SHA-384PRNG", CodeProvider.GNU_CRYPTO, true, true), 
	GNU_SHA512PRNG("SHA-512PRNG",CodeProvider.GNU_CRYPTO, true, true), 
	GNU_WIRLPOOLPRNG("WHIRLPOOLPRNG", CodeProvider.GNU_CRYPTO, true, true), 
	SPEEDIEST(SHA1PRNG), 
	NativePRNGBlocking("NativePRNG", CodeProvider.SUN, false, true), 
	BC_FIPS_APPROVED("BC_FIPS_APPROVED", CodeProvider.BCFIPS, false, false),
	BC_FIPS_APPROVED_FOR_KEYS("BC_FIPS_APPROVED_FOR_KEYS", CodeProvider.BCFIPS, false, false),
	DEFAULT_BC_FIPS_APPROVED("DEFAULT_BC_FIPS_APPROVED", CodeProvider.BCFIPS, false, false),
	GNU_DEFAULT(GNU_SHA1PRNG), 
	DEFAULT(DEFAULT_BC_FIPS_APPROVED);

	private final String algorithmeName;

	private final CodeProvider provider;

	private final boolean gnuVersion;
	
	private final boolean needInitialSeed;
	
	private static final Map<SecureRandomType, AbstractSecureRandom> singletons=Collections.synchronizedMap(new HashMap<SecureRandomType, AbstractSecureRandom>());
	
	private SecureRandomType(SecureRandomType type) {
		this(type.algorithmeName, type.provider, type.gnuVersion, type.needInitialSeed);
	}
	
	boolean needInitialSeed()
	{
		return needInitialSeed;
	}

	private SecureRandomType(String algorithmName, CodeProvider provider, boolean gnuVersion, boolean needInitialSeed) {
		this.algorithmeName = algorithmName;
		this.provider = provider;
		this.gnuVersion = gnuVersion;
		this.needInitialSeed=needInitialSeed;
	}
	
	/**
	 * 
	 * @param nonce               value to use in DRBG construction.
	 * @param personalizationString
	 * @return the secure random
	 * @throws gnu.vm.jgnu.security.NoSuchAlgorithmException if the algorithm was not found
	 * @throws gnu.vm.jgnu.security.NoSuchProviderException if the provider was not found
	 */
	public AbstractSecureRandom getInstance(byte nonce[]) throws gnu.vm.jgnu.security.NoSuchAlgorithmException, gnu.vm.jgnu.security.NoSuchProviderException
	{
		return getInstance(nonce, (byte[])null);
	}
	
	/**
	 * 
	 * @param nonce               value to use in DRBG construction.
	 * @param personalizationString
	 * @return the secure random
	 * @throws gnu.vm.jgnu.security.NoSuchAlgorithmException if the algorithm was not found
	 * @throws gnu.vm.jgnu.security.NoSuchProviderException if the provider was not found
	 */
	public AbstractSecureRandom getInstance(byte nonce[], String personalizationString) throws gnu.vm.jgnu.security.NoSuchAlgorithmException, gnu.vm.jgnu.security.NoSuchProviderException
	{
		return getInstance(nonce, personalizationString==null?null:personalizationString.getBytes());
	}
	
	/**
	 * 
	 * @param nonce               value to use in DRBG construction.
	 * @param personalizationString the personalisation string for the underlying DRBG.
	 * @return the secure random
	 * @throws gnu.vm.jgnu.security.NoSuchAlgorithmException if the algorithm was not found
	 * @throws gnu.vm.jgnu.security.NoSuchProviderException 
	 * @throws gnu.vm.jgnu.security.NoSuchProviderException if the provider was not found
	 */
	public AbstractSecureRandom getInstance(byte nonce[], byte[] personalizationString)
			throws gnu.vm.jgnu.security.NoSuchAlgorithmException, gnu.vm.jgnu.security.NoSuchProviderException {
		AbstractSecureRandom res=null;
		if (gnuVersion) {
			if (algorithmeName == null)
				res=new GnuSecureRandom(this, new gnu.vm.jgnu.security.SecureRandom());
			else
				res=new GnuSecureRandom(this, gnu.vm.jgnu.security.SecureRandom.getInstance(algorithmeName));
		} else {
			if (BC_FIPS_APPROVED.algorithmeName.equals(this.algorithmeName) || BC_FIPS_APPROVED_FOR_KEYS.algorithmeName.equals(this.algorithmeName))
			{
				CodeProvider.ensureBouncyCastleProviderLoaded();
				if (nonce==null)
				{
					nonce=new byte[32];
					SecureRandomType.SHA1PRNG.getInstance(null).nextBytes(nonce);
				}

				EntropySourceProvider entSource = new BasicEntropySourceProvider(new SecureRandom(), true);
				FipsDRBG.Builder drgbBldr = FipsDRBG.SHA512_HMAC.fromEntropySource(entSource)
						.setSecurityStrength(256)
						.setEntropyBitsRequired(256);
				if (personalizationString!=null)
				{
					drgbBldr=drgbBldr.setPersonalizationString(personalizationString);
				}
				SecureRandom sr=null;
				res=new JavaNativeSecureRandom(this, sr=drgbBldr.build(nonce,BC_FIPS_APPROVED_FOR_KEYS.algorithmeName.equals(this.algorithmeName)), false);
				if (BC_FIPS_APPROVED_FOR_KEYS.algorithmeName.equals(this.algorithmeName))
					CryptoServicesRegistrar.setSecureRandom(sr);
				return res;
			}
			else if (DEFAULT_BC_FIPS_APPROVED.algorithmeName.equals(this.algorithmeName))
			{
				CodeProvider.ensureBouncyCastleProviderLoaded();
				if (nonce==null)
				{
					nonce=new byte[32];
					SecureRandomType.SHA1PRNG.getInstance(null).nextBytes(nonce);
				}

				EntropySourceProvider entSource = new BasicEntropySourceProvider(new SecureRandom(), true);
				FipsDRBG.Builder drgbBldr = FipsDRBG.SHA512.fromEntropySource(entSource)
						.setSecurityStrength(256)
						.setEntropyBitsRequired(256);
				if (personalizationString!=null)
				{
					drgbBldr=drgbBldr.setPersonalizationString(personalizationString);
				}
				return new JavaNativeSecureRandom(this, drgbBldr.build(nonce,true), false);
			}
			else
			{
				try {
					
					if (algorithmeName == null)
						res=new JavaNativeSecureRandom(this, new SecureRandom());
					else
						res=new JavaNativeSecureRandom(this, SecureRandom.getInstance(algorithmeName, provider.name()));
				} catch (NoSuchAlgorithmException e) {
					throw new gnu.vm.jgnu.security.NoSuchAlgorithmException(e);
				} catch (NoSuchProviderException e) {
					throw new gnu.vm.jgnu.security.NoSuchProviderException(e.getMessage());
				}
			}
		}
		if (nonce!=null)
			res.setSeed(nonce);
		return res;

	}
	

	public AbstractSecureRandom getInstance(long seed)
			throws gnu.vm.jgnu.security.NoSuchAlgorithmException, gnu.vm.jgnu.security.NoSuchProviderException {
		byte[] nonce=new byte[8];
		Bits.putLong(nonce, 0, seed);
		return getInstance(seed);
	}

	public boolean isGNUVersion() {
		return gnuVersion;
	}
	
	public CodeProvider getProvider()
	{
		return provider;
	}
	
	
	final static byte[] nonce=("La piethagore\n" + 
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
	
	static
	{
		try
		{
			CryptoServicesRegistrar.setSecureRandom(DEFAULT.getInstance(nonce));
		}
		catch(Exception e)
		{
			e.printStackTrace();
		}
	}
	
	public AbstractSecureRandom getSingleton(byte nonce[]) throws gnu.vm.jgnu.security.NoSuchAlgorithmException, gnu.vm.jgnu.security.NoSuchProviderException
	{
		return getSingleton(nonce, null);
	}
	public AbstractSecureRandom getSingleton(byte nonce[], byte[] personalizationString) throws gnu.vm.jgnu.security.NoSuchAlgorithmException, gnu.vm.jgnu.security.NoSuchProviderException
	{
		return getSingleton(nonce, personalizationString, false);
	}
	public AbstractSecureRandom getSingleton(byte nonce[], byte[] personalizationString, boolean regenerate) throws gnu.vm.jgnu.security.NoSuchAlgorithmException, gnu.vm.jgnu.security.NoSuchProviderException
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
	
}

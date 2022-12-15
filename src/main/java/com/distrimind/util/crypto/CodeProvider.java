/*
Copyright or © or Corp. Jason Mahdjoub (04/02/2016)

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

import java.security.*;

import com.distrimind.util.OSVersion;
import com.distrimind.bouncycastle.crypto.CryptoServicesRegistrar;
import com.distrimind.bcfips.jcajce.provider.BouncyCastleFipsProvider;
import com.distrimind.bouncycastle.jce.provider.BouncyCastleProvider;
import com.distrimind.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;

import com.distrimind.util.OS;

/**
 * List of asymmetric encryption algorithms
 * 
 * @author Jason Mahdjoub
 * @version 3.0
 * @since Utils 2.9.0
 */
public enum CodeProvider {
	SUN, SunJCE, SunJSSE, SunRsaSign, SunEC, GNU_CRYPTO, BCFIPS, BC, BCPQC, AndroidOpenSSL;

	private static volatile Provider bouncyProvider = null;
	private static volatile Provider bouncyProviderFIPS = null;
	private static volatile Provider bouncyProviderPQC = null;
	private static volatile boolean init=false;

	private static Provider getBouncyCastleProvider() {

		if (bouncyProvider == null) {

			synchronized (CodeProvider.class) {
				if (bouncyProvider == null) {
					BouncyCastleProvider bc = new BouncyCastleProvider();
					bouncyProvider=bc;
					if (OSVersion.getCurrentOSVersion().getOS()==OS.ANDROID)
					{
						if (OSVersion.getCurrentOSVersion().compareTo(OSVersion.ANDROID_28_P)>=0) {
							Security.insertProviderAt(bc, Security.getProviders().length+1);
						}

					}
					else
						Security.insertProviderAt(bc, Security.getProviders().length+1);

					try {
						if (bouncyProviderFIPS==null)
							CryptoServicesRegistrar.setSecureRandom(SecureRandomType.JAVA_STRONG_DRBG.getSingleton(null));
						else {
							AbstractSecureRandom random=SecureRandomType.DEFAULT.getSingleton(null);
							CryptoServicesRegistrar.setSecureRandom(random);
							com.distrimind.bcfips.crypto.CryptoServicesRegistrar.setSecureRandom(random);
						}
					} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
						e.printStackTrace();
					}

				}
			}
		}
		return bouncyProvider;
	}

	private static Provider getBCFIPSProvider() {

		if (bouncyProviderFIPS == null) {

			synchronized (CodeProvider.class) {

				if (bouncyProviderFIPS == null) {
					BouncyCastleFipsProvider bc = new BouncyCastleFipsProvider();
					Security.insertProviderAt(bc, Security.getProviders().length+1);
					bouncyProviderFIPS=bc;
					try {
						if (bouncyProvider==null)
						{
							CryptoServicesRegistrar.setSecureRandom(SecureRandomType.DEFAULT_BC_FIPS_APPROVED.getSingleton(null));
						}
						else {
							AbstractSecureRandom random = SecureRandomType.DEFAULT.getSingleton(null);
							com.distrimind.bcfips.crypto.CryptoServicesRegistrar.setSecureRandom(random);
							CryptoServicesRegistrar.setSecureRandom(random);
						}
					} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
						e.printStackTrace();
					}
				}
			}
		}
		return bouncyProviderFIPS;
	}

	private static Provider getBQCProvider() {

		if (bouncyProviderPQC == null) {

			synchronized (CodeProvider.class) {

				if (bouncyProviderPQC == null) {
					BouncyCastlePQCProvider bc = new BouncyCastlePQCProvider();
					Security.insertProviderAt(bc, Security.getProviders().length+1);
					bouncyProviderPQC=bc;
				}
			}
		}
		return bouncyProviderPQC;
	}

	public String getCompatibleCodeProviderName()
	{
		return convertProviderToCompatibleProviderWithCurrentOS().name();
	}
	public Provider getCompatibleProvider() throws NoSuchProviderException {
		if (!init)
		{
			CodeProvider.init=true;
			Security.insertProviderAt(new UtilsSecurityProvider(), 1);
		}
		switch (this)
		{
			case BCFIPS:
				return getBCFIPSProvider();
			case BCPQC:
				return getBQCProvider();
			case BC:
				return getBouncyCastleProvider();
			case GNU_CRYPTO:
				GnuFunctions.checkGnuLoaded();
			default: {
				Provider p = Security.getProvider(getCompatibleCodeProviderName());
				if (p == null)
					throw new NoSuchProviderException();
				return p;
			}
		}
	}



	public CodeProvider convertProviderToCompatibleProviderWithCurrentOS()
	{
		if (OSVersion.getCurrentOSVersion()!=null && OSVersion.getCurrentOSVersion().getOS()==OS.ANDROID)
		{
			if (this==SUN || this==SunJCE || this==SunJSSE || this==SunRsaSign || this==SunEC) {
				if (OSVersion.getCurrentOSVersion().compareTo(OSVersion.ANDROID_28_P) < 0) {
					return BC;
				} else {
					return AndroidOpenSSL;
				}
			}
		}
		return this;
	}
	
}

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

import java.security.Provider;
import java.security.Security;

import com.distrimind.util.OSVersion;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;

import com.distrimind.util.OS;

/**
 * List of asymmetric encryption algorithms
 * 
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 2.9.0
 */
public enum CodeProvider {
	SUN, SunJCE, SunJSSE, SunRsaSign, SunEC, GNU_CRYPTO, BCFIPS, BC, BCPQC;

	private static volatile Provider bouncyProvider = null;
	private static volatile Provider bouncyProviderFIPS = null;
	private static volatile Provider bouncyProviderPQC = null;

	static void ensureBouncyCastleProviderLoaded() {

		if (bouncyProviderPQC == null) {

			synchronized (CodeProvider.class) {
				if (bouncyProviderPQC == null) {
					bouncyProviderPQC = new BouncyCastlePQCProvider();
					Security.insertProviderAt(bouncyProviderPQC, Security.getProviders().length+1);
				}
			}
		}
		if (bouncyProvider == null) {

			synchronized (CodeProvider.class) {
				if (bouncyProvider == null) {
					bouncyProvider = new BouncyCastleProvider();
					Security.insertProviderAt(bouncyProvider, Security.getProviders().length+1);
				}
			}
		}
		if (bouncyProviderFIPS == null) {

			synchronized (CodeProvider.class) {
				if (bouncyProviderFIPS == null) {
					bouncyProviderFIPS = new BouncyCastleFipsProvider();
					Security.insertProviderAt(bouncyProviderFIPS, Security.getProviders().length+1);
				}
			}
		}
	}

	CodeProvider checkProviderWithCurrentOS()
	{
		if (OSVersion.getCurrentOSVersion()!=null && OSVersion.getCurrentOSVersion().getOS()==OS.ANDROID)
		{
			if (this==SUN || this==SunJCE || this==SunJSSE || this==SunRsaSign || this==SunEC)
				return BC;
		}
		return this;
	}
	
}

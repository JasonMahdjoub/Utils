package com.distrimind.util.crypto;
/*
Copyright or © or Copr. Jason Mahdjoub (01/04/2013)

jason.mahdjoub@distri-mind.fr

This software (Object Oriented Database (OOD)) is a computer program 
whose purpose is to manage a local database with the object paradigm 
and the java langage 

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

import javax.crypto.IllegalBlockSizeException;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

/**
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 4.0.0
 */
class GnuFunctions {
	private static volatile boolean gnuLoaded=false;
	private static Method getSignatureAlgo=null;
	private static Method getCihperAlgo=null;
	private static Method getPublicKey=null;
	private static Method getPrivateKey=null;
	private static Method getEncoded=null;
	private static Method cipherInit=null;
	private static Method cipherInitUnwrap=null;
	private static Method cipherWrap=null;
	private static Method cipherUnwrap=null;

	private static Constructor<?> keyPairConstructor;
	private static int WRAP_MODE;
	private static int UNWRAP_MODE;
	private static int SECRET_KEY;


	private static void checkGnuLoaded()
	{
		if (!gnuLoaded)
		{
			synchronized (GnuFunctions.class)
			{
				if (!gnuLoaded)
				{
					try {
						getSignatureAlgo=Class.forName("gnu.vm.jgnu.security.Signature").getDeclaredMethod("getInstance", String.class);
						getCihperAlgo=Class.forName("gnu.vm.jgnux.crypto.Cipher").getDeclaredMethod("getInstance", String.class);
						getPublicKey=Class.forName("gnu.vm.jgnu.security.KeyPair").getDeclaredMethod("getPublic");
						getPrivateKey=Class.forName("gnu.vm.jgnu.security.KeyPair").getDeclaredMethod("getPrivate");
						getPrivateKey=Class.forName("gnu.vm.jgnu.security.KeyPair").getDeclaredMethod("getPrivate");
						getEncoded=Class.forName("gnu.vm.jgnu.security.Key").getDeclaredMethod("getEncoded");
						keyPairConstructor=Class.forName("gnu.vm.jgnu.security.KeyPair").getDeclaredConstructor(Class.forName("gnu.vm.jgnu.security.PublicKey"), Class.forName("gnu.vm.jgnu.security.PrivateKey"));
						cipherInit=Class.forName("gnu.vm.jgnux.crypto.Cipher").getMethod("init", int.class,Class.forName("gnu.vm.jgnu.security.Key"), Class.forName("gnu.vm.jgnu.security.SecureRandom") );
						cipherInitUnwrap=Class.forName("gnu.vm.jgnux.crypto.Cipher").getMethod("init", int.class,Class.forName("gnu.vm.jgnu.security.Key"));
						cipherWrap=Class.forName("gnu.vm.jgnux.crypto.Cipher").getMethod("wrap", Class.forName("gnu.vm.jgnu.security.Key"));
						cipherUnwrap=Class.forName("gnu.vm.jgnux.crypto.Cipher").getMethod("unwrap", byte[].class, String.class, int.class);

						WRAP_MODE=(int)Class.forName("gnu.vm.jgnux.crypto.Cipher").getDeclaredField("WRAP_MODE").get(null);
						UNWRAP_MODE=(int)Class.forName("gnu.vm.jgnux.crypto.Cipher").getDeclaredField("UNWRAP_MODE").get(null);
						SECRET_KEY=(int)Class.forName("gnu.vm.jgnux.crypto.Cipher").getDeclaredField("SECRET_KEY").get(null);
					} catch (NoSuchMethodException | ClassNotFoundException | NoSuchFieldException | IllegalAccessException e) {
						e.printStackTrace();
						System.exit(-1);
					}
					gnuLoaded=true;
				}
			}
		}
	}

	static Object getSignatureAlgorithm(String signatureName) throws NoSuchAlgorithmException {
		checkGnuLoaded();
		try {
			return getSignatureAlgo.invoke(null, signatureName);
		} catch (IllegalAccessException e) {
			throw new IllegalAccessError();
		} catch (InvocationTargetException e) {
			throw new NoSuchAlgorithmException(e.getTargetException());
		}
	}

	static Object getCipherAlgorithm(String signatureName) throws NoSuchAlgorithmException {
		checkGnuLoaded();
		try {
			return getCihperAlgo.invoke(null, signatureName);
		} catch (IllegalAccessException e) {
			throw new IllegalAccessError();
		} catch (InvocationTargetException e) {
			throw new NoSuchAlgorithmException(e.getTargetException());
		}
	}

	static void cipherInitWrapMode(Object cipher, Object publicKey, Object random) throws InvalidKeyException {
		checkGnuLoaded();
		try {
			cipherInit.invoke(cipher, WRAP_MODE, publicKey, random);
		} catch (IllegalAccessException e) {
			throw new IllegalAccessError();
		} catch (InvocationTargetException e) {
			throw new InvalidKeyException(e.getTargetException());
		}
	}

	static void cipherInitUnwrapMode(Object cipher, Object privateKey) throws InvalidKeyException {
		checkGnuLoaded();
		try {
			cipherInitUnwrap.invoke(cipher, UNWRAP_MODE, privateKey);
		} catch (IllegalAccessException e) {
			throw new IllegalAccessError();
		} catch (InvocationTargetException e) {
			throw new InvalidKeyException(e.getTargetException());
		}
	}


	static void cipherWrap(Object cipher, Object keyToWrap) throws IllegalStateException, IllegalBlockSizeException, InvalidKeyException {
		checkGnuLoaded();
		try {
			cipherWrap.invoke(cipher, keyToWrap);
		} catch (IllegalAccessException e) {
			throw new IllegalAccessError();
		} catch (InvocationTargetException e) {
			if (e.getTargetException() instanceof IllegalStateException)
			 	throw (IllegalStateException)e.getTargetException();
			if (e.getTargetException() instanceof InvalidKeyException)
				throw (InvalidKeyException)e.getTargetException();
			else if (e.getTargetException().getClass().getName().equals("gnu.vm.jgnux.crypto.InvalidKeyException"))
				throw new InvalidKeyException(e);
			else if (e.getTargetException().getClass().getName().equals("gnu.vm.jgnux.crypto.IllegalBlockSizeException"))
				throw new IllegalBlockSizeException(e.getMessage());
			else if (e.getTargetException().getClass().getName().equals("gnu.vm.jgnu.security.InvalidKeyException"))
				throw new InvalidKeyException(e);
			throw new IllegalAccessError();
		}
	}

	static void cipherUnwrap(Object cipher, byte[] keyToUnwrap, String algorithmName) throws IllegalStateException, InvalidKeyException, NoSuchAlgorithmException  {
		checkGnuLoaded();
		try {
			cipherUnwrap.invoke(cipher, keyToUnwrap, algorithmName, SECRET_KEY);
		} catch (IllegalAccessException e) {
			throw new IllegalAccessError();
		} catch (InvocationTargetException e) {
			if (e.getTargetException() instanceof IllegalStateException)
				throw (IllegalStateException)e.getTargetException();
			if (e.getTargetException() instanceof InvalidKeyException)
				throw (InvalidKeyException)e.getTargetException();
			else if (e.getTargetException().getClass().getName().equals("gnu.vm.jgnux.crypto.InvalidKeyException"))
				throw new InvalidKeyException(e);
			else if (e.getTargetException().getClass().getName().equals("gnu.vm.jgnu.security.NoSuchAlgorithmException"))
				throw new NoSuchAlgorithmException(e);
			throw new IllegalAccessError();
		}
	}

	static Object getPublicKey(Object keyPair) {
		checkGnuLoaded();
		try {
			return getPublicKey.invoke(keyPair);
		} catch (IllegalAccessException | InvocationTargetException e) {
			throw new IllegalAccessError();
		}
	}

	static Object getPrivateKey(Object keyPair) {
		checkGnuLoaded();
		try {
			return getPrivateKey.invoke(keyPair);
		} catch (IllegalAccessException | InvocationTargetException e) {
			throw new IllegalAccessError();
		}
	}
	static byte[] getEncoded(Object key) {
		checkGnuLoaded();
		try {
			return (byte[])getEncoded.invoke(key);
		} catch (IllegalAccessException | InvocationTargetException e) {
			throw new IllegalAccessError();
		}
	}

	static Object getKeyPairInstance(Object publicKey, Object privateKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
		try {
			return keyPairConstructor.newInstance(publicKey, privateKey);
		} catch (InstantiationException | IllegalAccessException e) {
			throw new IllegalAccessError();
		} catch (InvocationTargetException e) {
			if (e.getTargetException().getClass().getName().equals("gnu.vm.jgnu.security.NoSuchAlgorithmException"))
				throw new NoSuchAlgorithmException(e.getTargetException());
			else if (e.getTargetException().getClass().getName().equals("gnu.vm.jgnu.security.spec.InvalidKeySpecException"))
				throw new InvalidKeySpecException(e);
			e.printStackTrace();
			throw new IllegalAccessError();
		}
	}


}

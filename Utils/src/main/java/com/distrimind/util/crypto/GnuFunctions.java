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


import gnu.vm.jgnux.crypto.Cipher;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.*;
import java.security.*;
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
	private static Method cipherInitIntKeyRandom =null;
	private static Method cipherInitUnwrap=null;
	private static Method cipherWrap=null;
	private static Method cipherUnwrap=null;
	private static Method cipherDoFinal=null, cipherInitIntKeyParamSpec =null, cipherDoFinalBytesInt=null,
			cipherDoFinalBytesIntInt=null, cipherDoFinalBytesIntIntBytesInt=null,  cipherGetAlgorithm=null, cipherGetIv=null,
			cipherGetOutputSize=null, cipherUpdateBytesIntInt=null, cipherUpdateBytesIntIntBytesInt=null, cipherGetBlockSize=null ;
	private static Method engineSetSeed=null, engineNextBytes=null, engineGenerateSeed=null;

	private static Constructor<?> keyPairConstructor;
	private static Constructor<?> secureRandomFromSpiConstructor;
	private static Constructor<?> IVparamSpec;
	private static Constructor<?> constCipherInputStream, consCipherOutputStream;

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
						cipherInitIntKeyRandom =Class.forName("gnu.vm.jgnux.crypto.Cipher").getMethod("init", int.class,Class.forName("gnu.vm.jgnu.security.Key"), Class.forName("gnu.vm.jgnu.security.SecureRandom") );
						cipherInitIntKeyParamSpec =Class.forName("gnu.vm.jgnux.crypto.Cipher").getMethod("init", int.class, Class.forName("gnu.vm.jgnu.security.Key"), Class.forName("gnu.vm.jgnu.security.spec.AlgorithmParameterSpec"));
						cipherInitUnwrap=Class.forName("gnu.vm.jgnux.crypto.Cipher").getMethod("init", int.class,Class.forName("gnu.vm.jgnu.security.Key"));
						cipherWrap=Class.forName("gnu.vm.jgnux.crypto.Cipher").getMethod("wrap", Class.forName("gnu.vm.jgnu.security.Key"));
						cipherUnwrap=Class.forName("gnu.vm.jgnux.crypto.Cipher").getMethod("unwrap", byte[].class, String.class, int.class);
						cipherDoFinal=Class.forName("gnu.vm.jgnux.crypto.Cipher").getMethod("doFinal");

						cipherDoFinalBytesInt=Class.forName("gnu.vm.jgnux.crypto.Cipher").getMethod("doFinal", byte[].class, int.class);
						cipherDoFinalBytesIntInt=Class.forName("gnu.vm.jgnux.crypto.Cipher").getMethod("doFinal", byte[].class, int.class, int.class);
						cipherDoFinalBytesIntIntBytesInt=Class.forName("gnu.vm.jgnux.crypto.Cipher").getMethod("doFinal", byte[].class, int.class, int.class, byte[].class, int.class);
						cipherGetAlgorithm=Class.forName("gnu.vm.jgnux.crypto.Cipher").getMethod("getAlgorithm");
						cipherGetIv=Class.forName("gnu.vm.jgnux.crypto.Cipher").getMethod("getIV");
						cipherGetBlockSize=Class.forName("gnu.vm.jgnux.crypto.Cipher").getMethod("getBlockSize");
						cipherGetOutputSize=Class.forName("gnu.vm.jgnux.crypto.Cipher").getMethod("getOutputSize", int.class);
						cipherUpdateBytesIntInt=Class.forName("gnu.vm.jgnux.crypto.Cipher").getMethod("update", byte[].class, int.class, int.class);
						cipherUpdateBytesIntIntBytesInt=Class.forName("gnu.vm.jgnux.crypto.Cipher").getMethod("update", byte[].class, int.class, int.class, byte[].class, int.class);
						IVparamSpec=Class.forName("gnu.vm.jgnux.crypto.spec.IvParameterSpec").getDeclaredConstructor(byte[].class);
						constCipherInputStream=Class.forName("gnu.vm.jgnux.crypto.CipherInputStream").getDeclaredConstructor(InputStream.class, Cipher.class);
						consCipherOutputStream=Class.forName("gnu.vm.jgnux.crypto.CipherOutputStream").getDeclaredConstructor(OutputStream.class, Cipher.class);


						WRAP_MODE=(int)Class.forName("gnu.vm.jgnux.crypto.Cipher").getDeclaredField("WRAP_MODE").get(null);
						UNWRAP_MODE=(int)Class.forName("gnu.vm.jgnux.crypto.Cipher").getDeclaredField("UNWRAP_MODE").get(null);
						SECRET_KEY=(int)Class.forName("gnu.vm.jgnux.crypto.Cipher").getDeclaredField("SECRET_KEY").get(null);

						//noinspection JavaReflectionMemberAccess
						engineSetSeed=Class.forName("gnu.vm.jgnu.security.SecureRandomSpi").getMethod("engineSetSeed", byte[].class);
						//noinspection JavaReflectionMemberAccess
						engineNextBytes=Class.forName("gnu.vm.jgnu.security.SecureRandomSpi").getMethod("engineNextBytes", byte[].class);
						//noinspection JavaReflectionMemberAccess
						engineGenerateSeed=Class.forName("gnu.vm.jgnu.security.SecureRandomSpi").getMethod("engineGenerateSeed", int.class);
						secureRandomFromSpiConstructor=Class.forName("gnu.vm.jgnu.security.SecureRandom").getDeclaredConstructor(Class.forName("gnu.vm.jgnu.security.SecureRandomSpi"), Class.forName("gnu.vm.jgnu.security.Provider"));


						AccessController.doPrivileged(new PrivilegedAction<Void>() {
							@Override
							public Void run() {
								secureRandomFromSpiConstructor.setAccessible(true);
								return null;
							}
						});


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
			cipherInitIntKeyRandom.invoke(cipher, WRAP_MODE, publicKey, random);
		} catch (IllegalAccessException e) {
			throw new IllegalAccessError();
		} catch (InvocationTargetException e) {
			throw new InvalidKeyException(e.getTargetException());
		}
	}

	static void cipherInit(Object cipher, int mode, Object publicKey, Object random) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException {
		checkGnuLoaded();
		try {
			cipherInitIntKeyRandom.invoke(cipher, mode, publicKey, random);
		} catch (IllegalAccessException e) {
			throw new IllegalAccessError();
		} catch (InvocationTargetException e) {
			if (e.getTargetException() instanceof IllegalStateException)
				throw (IllegalStateException)e.getTargetException();
			if (e.getTargetException().getClass().getName().equals("gnu.vm.jgnu.security.InvalidKeyException") )
				throw new InvalidKeyException(e.getTargetException());
			if (e.getTargetException().getClass().getName().equals("gnu.vm.jgnu.security.NoSuchAlgorithmException") )
				throw new NoSuchAlgorithmException(e.getTargetException());
			if (e.getTargetException().getClass().getName().equals("gnu.vm.jgnu.security.spec.InvalidKeySpecException") )
				throw new InvalidKeySpecException(e.getTargetException());
			throw new IllegalStateException(e.getTargetException());
		}
	}
	static void cipherInit(Object cipher, int mode, Object publicKey, byte[] _iv) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidAlgorithmParameterException {
		checkGnuLoaded();
		try {
			cipherInitIntKeyParamSpec.invoke(cipher, mode, publicKey, IVparamSpec.newInstance((Object)_iv));
		} catch (IllegalAccessException | InstantiationException e) {
			throw new IllegalAccessError();
		} catch (InvocationTargetException e) {
			if (e.getTargetException() instanceof IllegalStateException)
				throw (IllegalStateException)e.getTargetException();
			if (e.getTargetException().getClass().getName().equals("gnu.vm.jgnu.security.InvalidKeyException") )
				throw new InvalidKeyException(e.getTargetException());
			if (e.getTargetException().getClass().getName().equals("gnu.vm.jgnu.security.NoSuchAlgorithmException") )
				throw new NoSuchAlgorithmException(e.getTargetException());
			if (e.getTargetException().getClass().getName().equals("gnu.vm.jgnu.security.spec.InvalidKeySpecException") )
				throw new InvalidKeySpecException(e.getTargetException());
			if (e.getTargetException().getClass().getName().equals("gnu.vm.jgnu.security.InvalidAlgorithmParameterException") )
				throw new InvalidAlgorithmParameterException(e.getTargetException());
			throw new IllegalStateException(e.getTargetException());

		}
	}
	static byte[] cipherDoFinal(Object cipher) throws IllegalStateException, IllegalBlockSizeException, BadPaddingException {
		checkGnuLoaded();
		try {
			return (byte[])cipherDoFinal.invoke(cipher);
		} catch (IllegalAccessException e) {
			throw new IllegalAccessError();
		} catch (InvocationTargetException e) {
			if (e.getTargetException() instanceof IllegalStateException)
				throw (IllegalStateException)e.getTargetException();
			if (e.getTargetException().getClass().getName().equals("gnu.vm.jgnux.crypto.IllegalBlockSizeException") )
				throw new IllegalBlockSizeException(e.getTargetException().getMessage());
			if (e.getTargetException().getClass().getName().equals("gnu.vm.jgnux.crypto.BadPaddingException") )
				throw new BadPaddingException(e.getTargetException().getMessage());
			throw new IllegalStateException(e.getTargetException());
		}
	}
	static int cipherDoFinal(Object cipher, byte[] _output, int _outputOffset) throws IllegalStateException, IllegalBlockSizeException, BadPaddingException, ShortBufferException {
		checkGnuLoaded();
		try {
			return (int)cipherDoFinalBytesInt.invoke(cipher, _output, _outputOffset);
		} catch (IllegalAccessException e) {
			throw new IllegalAccessError();
		} catch (InvocationTargetException e) {
			if (e.getTargetException() instanceof IllegalStateException)
				throw (IllegalStateException)e.getTargetException();
			if (e.getTargetException().getClass().getName().equals("gnu.vm.jgnux.crypto.ShortBufferException") )
				throw new ShortBufferException(e.getTargetException().getMessage());
			if (e.getTargetException().getClass().getName().equals("gnu.vm.jgnux.crypto.IllegalBlockSizeException") )
				throw new IllegalBlockSizeException(e.getTargetException().getMessage());
			if (e.getTargetException().getClass().getName().equals("gnu.vm.jgnux.crypto.BadPaddingException") )
				throw new BadPaddingException(e.getTargetException().getMessage());
			throw new IllegalStateException(e.getTargetException());
		}
	}
	static byte[] cipherDoFinal(Object cipher, byte[] _input, int _inputOffset, int _inputLength) throws IllegalStateException, IllegalBlockSizeException, BadPaddingException {
		checkGnuLoaded();
		try {
			return (byte[])cipherDoFinalBytesIntInt.invoke(cipher, _input, _inputOffset, _inputLength);
		} catch (IllegalAccessException e) {
			throw new IllegalAccessError();
		} catch (InvocationTargetException e) {
			if (e.getTargetException() instanceof IllegalStateException)
				throw (IllegalStateException)e.getTargetException();
			if (e.getTargetException().getClass().getName().equals("gnu.vm.jgnux.crypto.IllegalBlockSizeException") )
				throw new IllegalBlockSizeException(e.getTargetException().getMessage());
			if (e.getTargetException().getClass().getName().equals("gnu.vm.jgnux.crypto.BadPaddingException") )
				throw new BadPaddingException(e.getTargetException().getMessage());
			throw new IllegalStateException(e.getTargetException());
		}
	}

	static int cipherDoFinal(Object cipher, byte[] _input, int _inputOffset, int _inputLength, byte[] _output, int _outputOffset) throws IllegalStateException, IllegalBlockSizeException, BadPaddingException, ShortBufferException {
		checkGnuLoaded();
		try {
			return (int)cipherDoFinalBytesIntIntBytesInt.invoke(cipher, _input, _inputOffset, _inputLength, _output, _outputOffset);
		} catch (IllegalAccessException e) {
			throw new IllegalAccessError();
		} catch (InvocationTargetException e) {
			if (e.getTargetException() instanceof IllegalStateException)
				throw (IllegalStateException)e.getTargetException();
			if (e.getTargetException().getClass().getName().equals("gnu.vm.jgnux.crypto.ShortBufferException") )
				throw new ShortBufferException(e.getTargetException().getMessage());
			if (e.getTargetException().getClass().getName().equals("gnu.vm.jgnux.crypto.IllegalBlockSizeException") )
				throw new IllegalBlockSizeException(e.getTargetException().getMessage());
			if (e.getTargetException().getClass().getName().equals("gnu.vm.jgnux.crypto.BadPaddingException") )
				throw new BadPaddingException(e.getTargetException().getMessage());
			throw new IllegalStateException(e.getTargetException());
		}
	}

	static String cipherGetAlgorithm(Object cipher)  {
		checkGnuLoaded();
		try {
			return (String)cipherGetAlgorithm.invoke(cipher);
		} catch (IllegalAccessException e) {
			throw new IllegalAccessError();
		} catch (InvocationTargetException e) {
			throw new IllegalStateException(e.getTargetException());
		}
	}
	static int cipherGetBlockSize(Object cipher)  {
		checkGnuLoaded();
		try {
			return (int)cipherGetBlockSize.invoke(cipher);
		} catch (IllegalAccessException e) {
			throw new IllegalAccessError();
		} catch (InvocationTargetException e) {
			throw new IllegalStateException(e.getTargetException());
		}
	}

	static byte[] cipherGetIV(Object cipher)  {
		checkGnuLoaded();
		try {
			return (byte[])cipherGetIv.invoke(cipher);
		} catch (IllegalAccessException e) {
			throw new IllegalAccessError();
		} catch (InvocationTargetException e) {
			throw new IllegalStateException(e.getTargetException());
		}
	}
	static int cipherGetOutputSize(Object cipher, int _inputLength) throws IllegalStateException {
		checkGnuLoaded();
		try {
			return (int)cipherGetOutputSize.invoke(cipher, _inputLength);
		} catch (IllegalAccessException e) {
			throw new IllegalAccessError();
		} catch (InvocationTargetException e) {
			if (e.getTargetException() instanceof IllegalStateException)
				throw (IllegalStateException)e.getTargetException();
			throw new IllegalStateException(e.getTargetException());
		}
	}

	static byte[] cipherUpdate(Object cipher,byte[] _input, int _inputOffset, int _inputLength) throws IllegalStateException {
		checkGnuLoaded();
		try {
			return (byte[])cipherUpdateBytesIntInt.invoke(cipher, _input, _inputOffset, _inputLength);
		} catch (IllegalAccessException e) {
			throw new IllegalAccessError();
		} catch (InvocationTargetException e) {
			if (e.getTargetException() instanceof IllegalStateException)
				throw (IllegalStateException)e.getTargetException();
			throw new IllegalStateException(e.getTargetException());
		}
	}
	static int cipherUpdate(Object cipher,byte[] _input, int _inputOffset, int _inputLength, byte[] _output, int _outputOffset) throws IllegalStateException, ShortBufferException {
		checkGnuLoaded();
		try {
			return (int)cipherUpdateBytesIntIntBytesInt.invoke(cipher, _input, _inputOffset, _inputLength, _output, _outputOffset);
		} catch (IllegalAccessException e) {
			throw new IllegalAccessError();
		} catch (InvocationTargetException e) {
			if (e.getTargetException() instanceof IllegalStateException)
				throw (IllegalStateException)e.getTargetException();
			if (e.getTargetException().getClass().getName().equals("gnu.vm.jgnux.crypto.ShortBufferException") )
				throw new ShortBufferException(e.getTargetException().getMessage());
			throw new IllegalStateException(e.getTargetException());
		}
	}
	static InputStream cipherGetCipherInputStream(Object cipher,InputStream in)  {
		checkGnuLoaded();
		try {
			return (InputStream)constCipherInputStream.newInstance(in, cipher);
		} catch (IllegalAccessException | InstantiationException e) {
			throw new IllegalAccessError();
		} catch (InvocationTargetException e) {
			throw new IllegalStateException(e.getTargetException());
		}
	}
	static OutputStream cipherGetCipherOutputStream(Object cipher,OutputStream out)  {
		checkGnuLoaded();
		try {
			return (OutputStream)consCipherOutputStream.newInstance(out, cipher);
		} catch (IllegalAccessException | InstantiationException e) {
			throw new IllegalAccessError();
		} catch (InvocationTargetException e) {
			throw new IllegalStateException(e.getTargetException());
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
				throw new InvalidKeyException(e.getTargetException());
			else if (e.getTargetException().getClass().getName().equals("gnu.vm.jgnux.crypto.IllegalBlockSizeException"))
				throw new IllegalBlockSizeException(e.getTargetException().getMessage());
			else if (e.getTargetException().getClass().getName().equals("gnu.vm.jgnu.security.InvalidKeyException"))
				throw new InvalidKeyException(e.getTargetException());
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
				throw new InvalidKeyException(e.getTargetException());
			else if (e.getTargetException().getClass().getName().equals("gnu.vm.jgnu.security.NoSuchAlgorithmException"))
				throw new NoSuchAlgorithmException(e.getTargetException());
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
		checkGnuLoaded();
		try {
			return keyPairConstructor.newInstance(publicKey, privateKey);
		} catch (InstantiationException | IllegalAccessException e) {
			throw new IllegalAccessError();
		} catch (InvocationTargetException e) {
			if (e.getTargetException().getClass().getName().equals("gnu.vm.jgnu.security.NoSuchAlgorithmException"))
				throw new NoSuchAlgorithmException(e.getTargetException());
			else if (e.getTargetException().getClass().getName().equals("gnu.vm.jgnu.security.spec.InvalidKeySpecException"))
				throw new InvalidKeySpecException(e.getTargetException());
			e.printStackTrace();
			throw new IllegalAccessError();
		}
	}

	private static class IH implements InvocationHandler
	{
		final AbstractSecureRandom.AbstractSecureRandomSpi secureRandom;
		boolean initialized=false;

		public IH(AbstractSecureRandom.AbstractSecureRandomSpi secureRandom) {
			this.secureRandom = secureRandom;
		}

		@Override
		public Object invoke(Object proxy, Method method, Object[] args)  {
			if (method.equals(engineSetSeed))
			{
				if (initialized)
					secureRandom.engineSetSeed((byte[])args[0]);
			}
			else if (method.equals(engineNextBytes))
				if (initialized)
					secureRandom.engineNextBytes((byte[])args[0]);
			else
			if (method.equals(engineGenerateSeed))
				secureRandom.engineGenerateSeed((int)args[0]);
			return null;
		}
	}

	static Object getGnuRandomInterface(final AbstractSecureRandom.AbstractSecureRandomSpi secureRandom) {
		checkGnuLoaded();
		try {
			Class<?> c= Class.forName("gnu.vm.jgnu.security.SecureRandomSpi");
			IH ih=new IH(secureRandom);
			Object o= Proxy.newProxyInstance(c.getClassLoader(),
					new Class[]{c},
					ih);
			o=secureRandomFromSpiConstructor.newInstance(o, null);
			ih.initialized=true;
			return o;
		} catch (ClassNotFoundException | InstantiationException | IllegalAccessException | InvocationTargetException e) {
			throw new IllegalStateException(e);
		}
	}


}

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


import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.*;
import java.nio.ByteBuffer;
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
	private static Method cipherInitIntKeyRandom =null, cipherInitIntKey;
	private static Method cipherInitUnwrap=null;
	private static Method cipherWrap=null;
	private static Method cipherUnwrapByteStringInt =null;
	private static Method cipherDoFinal=null, cipherInitIntKeyParamSpec =null, cipherDoFinalBytesInt=null,
			cipherDoFinalBytesIntInt=null, cipherDoFinalBytesIntIntBytesInt=null,  cipherGetAlgorithm=null, cipherGetIv=null,
			cipherGetOutputSize=null, cipherUpdateBytesIntInt=null, cipherUpdateBytesIntIntBytesInt=null, cipherGetBlockSize=null, cipherGetInstance, cipherInitIntSymKey ;
	private static Method engineSetSeed=null, engineNextBytes=null, engineGenerateSeed=null;
	private static Method keyGeneratorGenerateKey, keyGeneratorGetAlgorithm, keyGeneratorGetProvider, keyGeneratorInit;
	private static Method keyPairGeneratorGenerateKeyPair, keyPairGeneratorGetAlgorithm,  keyPairGeneratorInit,  keyPairGeneratorInitRandom;
	private static Method macGetInstance, macDoFinal, macDoFinalBytes, macDoFinalBytesInt,macGetAlgorithm, macGetMacLength, macInit, macReset, macUpdateByte, macUpdateBytesIntInt,macUpdateByteBuffer;
	private static Method clone;
	private static Method keyFactGetInstance, keyFactGeneratePublic, keyFactGeneratePrivate;
	private static Method digestGetInstance, digestDigest,digestDigestBytes,  digestDigestBytesIntInt, digestGetAlgorithm, digestGetDigestLength,
			digestGetProvider, providerGetName, digestReset, digestUpdateByte, digestUpdateBytes, digestUpdateBytesIntInt, digestUpdateByteBuffer;
	private static Method secureRandomSetSeed, secureRandomNextBytes, secureRandomGenerateSeed, secureRandomGetInstance;
	private static Method signatureGetAlgorithm, signatureGetProviderName, signatureInitSignPriv, signatureInitSignPrivRand,
			signatureInitVerifPub, signatureSign, signatureSignBytesIntInt, signatureUpdateByte, signatureUpdateBytes, signatureUpdateBytesIntInt, signatureUpdateByteBuffer,
			signatureVerifyBytes, signatureVerifyBytesIntInt;
	private static Method keyGeneratorGetInstance;
	private static Method secretKeyFactoryGetInstance;
	private static Method secretKeyFactoryGenerateSecret;

	private static Constructor<?> keyPairConstructorPublicPrivate, keyPairGeneratorConstructorString ;
	private static Constructor<?> secureRandomFromSpiConstructor;
	private static Constructor<?> IVparamSpec;
	private static Constructor<?> constCipherInputStream, consCipherOutputStream;
	private static Constructor<?> constSecretKeySpec, constSecretKeySpecBytesIntIntString;
	private static Constructor<?> constPKCS8EncodedKeySpec, constX509EncodedKeySpec;
	private static Constructor<?> constPBEKeySpecCharsBytesIntInt;
	private static Constructor<?> constSecureRandom;





	private static int WRAP_MODE;
	private static int UNWRAP_MODE;
	private static int SECRET_KEY;


	static void checkGnuLoaded()
	{
		if (!gnuLoaded)
		{
			synchronized (GnuFunctions.class)
			{
				if (!gnuLoaded)
				{
					try {
						secretKeyFactoryGetInstance=Class.forName("gnu.vm.jgnux.crypto.SecretKeyFactory").getDeclaredMethod("getInstance", String.class);
						secretKeyFactoryGenerateSecret =Class.forName("gnu.vm.jgnux.crypto.SecretKeyFactory").getDeclaredMethod("generateSecret", Class.forName("gnu.vm.jgnu.security.spec.KeySpec") );
						constPBEKeySpecCharsBytesIntInt=Class.forName("gnu.vm.jgnux.crypto.spec.PBEKeySpec").getDeclaredConstructor(char[].class, byte[].class, int.class, int.class);

						getSignatureAlgo=Class.forName("gnu.vm.jgnu.security.Signature").getDeclaredMethod("getInstance", String.class);
						getCihperAlgo=Class.forName("gnu.vm.jgnux.crypto.Cipher").getDeclaredMethod("getInstance", String.class);
						getPublicKey=Class.forName("gnu.vm.jgnu.security.KeyPair").getDeclaredMethod("getPublic");
						getPrivateKey=Class.forName("gnu.vm.jgnu.security.KeyPair").getDeclaredMethod("getPrivate");
						getPrivateKey=Class.forName("gnu.vm.jgnu.security.KeyPair").getDeclaredMethod("getPrivate");
						getEncoded=Class.forName("gnu.vm.jgnu.security.Key").getDeclaredMethod("getEncoded");
						keyPairConstructorPublicPrivate =Class.forName("gnu.vm.jgnu.security.KeyPair").getDeclaredConstructor(Class.forName("gnu.vm.jgnu.security.PublicKey"), Class.forName("gnu.vm.jgnu.security.PrivateKey"));
						keyPairGeneratorConstructorString =Class.forName("gnu.vm.jgnu.security.KeyPairGenerator").getDeclaredConstructor(String.class);
						cipherInitIntSymKey =Class.forName("gnu.vm.jgnux.crypto.Cipher").getDeclaredMethod("init", int.class,Class.forName("gnu.vm.jgnu.security.Key"));
						cipherInitIntKeyRandom =Class.forName("gnu.vm.jgnux.crypto.Cipher").getDeclaredMethod("init", int.class,Class.forName("gnu.vm.jgnu.security.Key"), Class.forName("gnu.vm.jgnu.security.SecureRandom") );
						cipherInitIntKeyParamSpec =Class.forName("gnu.vm.jgnux.crypto.Cipher").getDeclaredMethod("init", int.class, Class.forName("gnu.vm.jgnu.security.Key"), Class.forName("gnu.vm.jgnu.security.spec.AlgorithmParameterSpec"));
						cipherInitUnwrap=Class.forName("gnu.vm.jgnux.crypto.Cipher").getDeclaredMethod("init", int.class,Class.forName("gnu.vm.jgnu.security.Key"));
						cipherWrap=Class.forName("gnu.vm.jgnux.crypto.Cipher").getDeclaredMethod("wrap", Class.forName("gnu.vm.jgnu.security.Key"));
						cipherUnwrapByteStringInt =Class.forName("gnu.vm.jgnux.crypto.Cipher").getDeclaredMethod("unwrap", byte[].class, String.class, int.class);
						cipherInitIntKey =Class.forName("gnu.vm.jgnux.crypto.Cipher").getDeclaredMethod("init", int.class, Class.forName("gnu.vm.jgnu.security.Key"));
						cipherDoFinal=Class.forName("gnu.vm.jgnux.crypto.Cipher").getDeclaredMethod("doFinal");

						cipherDoFinalBytesInt=Class.forName("gnu.vm.jgnux.crypto.Cipher").getDeclaredMethod("doFinal", byte[].class, int.class);
						cipherDoFinalBytesIntInt=Class.forName("gnu.vm.jgnux.crypto.Cipher").getDeclaredMethod("doFinal", byte[].class, int.class, int.class);
						cipherDoFinalBytesIntIntBytesInt=Class.forName("gnu.vm.jgnux.crypto.Cipher").getDeclaredMethod("doFinal", byte[].class, int.class, int.class, byte[].class, int.class);
						cipherGetAlgorithm=Class.forName("gnu.vm.jgnux.crypto.Cipher").getDeclaredMethod("getAlgorithm");
						cipherGetIv=Class.forName("gnu.vm.jgnux.crypto.Cipher").getDeclaredMethod("getIV");
						cipherGetBlockSize=Class.forName("gnu.vm.jgnux.crypto.Cipher").getDeclaredMethod("getBlockSize");
						cipherGetOutputSize=Class.forName("gnu.vm.jgnux.crypto.Cipher").getDeclaredMethod("getOutputSize", int.class);
						cipherUpdateBytesIntInt=Class.forName("gnu.vm.jgnux.crypto.Cipher").getDeclaredMethod("update", byte[].class, int.class, int.class);
						cipherUpdateBytesIntIntBytesInt=Class.forName("gnu.vm.jgnux.crypto.Cipher").getDeclaredMethod("update", byte[].class, int.class, int.class, byte[].class, int.class);
						cipherGetInstance=Class.forName("gnu.vm.jgnux.crypto.Cipher").getDeclaredMethod("getInstance", String.class);
						IVparamSpec=Class.forName("gnu.vm.jgnux.crypto.spec.IvParameterSpec").getDeclaredConstructor(byte[].class);
						constCipherInputStream=Class.forName("gnu.vm.jgnux.crypto.CipherInputStream").getDeclaredConstructor(InputStream.class, Class.forName("gnu.vm.jgnux.crypto.Cipher"));
						consCipherOutputStream=Class.forName("gnu.vm.jgnux.crypto.CipherOutputStream").getDeclaredConstructor(OutputStream.class, Class.forName("gnu.vm.jgnux.crypto.Cipher"));


						keyGeneratorGetInstance=Class.forName("gnu.vm.jgnux.crypto.KeyGenerator").getDeclaredMethod("getInstance", String.class);


						WRAP_MODE=(int)Class.forName("gnu.vm.jgnux.crypto.Cipher").getDeclaredField("WRAP_MODE").get(null);
						UNWRAP_MODE=(int)Class.forName("gnu.vm.jgnux.crypto.Cipher").getDeclaredField("UNWRAP_MODE").get(null);
						SECRET_KEY=(int)Class.forName("gnu.vm.jgnux.crypto.Cipher").getDeclaredField("SECRET_KEY").get(null);

						engineSetSeed=Class.forName("gnu.vm.jgnu.security.SecureRandomSpi").getDeclaredMethod("engineSetSeed", byte[].class);
						engineNextBytes=Class.forName("gnu.vm.jgnu.security.SecureRandomSpi").getDeclaredMethod("engineNextBytes", byte[].class);
						engineGenerateSeed=Class.forName("gnu.vm.jgnu.security.SecureRandomSpi").getDeclaredMethod("engineGenerateSeed", int.class);
						secureRandomFromSpiConstructor=Class.forName("gnu.vm.jgnu.security.SecureRandom").getDeclaredConstructor(Class.forName("gnu.vm.jgnu.security.SecureRandomSpi"), Class.forName("gnu.vm.jgnu.security.Provider"));
						constSecureRandom=Class.forName("gnu.vm.jgnu.security.SecureRandom").getDeclaredConstructor();
						secureRandomGetInstance=Class.forName("gnu.vm.jgnu.security.SecureRandom").getDeclaredMethod("getInstance", String.class);


						keyGeneratorGenerateKey=Class.forName("gnu.vm.jgnux.crypto.KeyGenerator").getDeclaredMethod("generateKey" );
						keyGeneratorGetAlgorithm=Class.forName("gnu.vm.jgnux.crypto.KeyGenerator").getDeclaredMethod("getAlgorithm");
						keyGeneratorGetProvider =Class.forName("gnu.vm.jgnux.crypto.KeyGenerator").getDeclaredMethod("getProvider");
						keyGeneratorInit=Class.forName("gnu.vm.jgnux.crypto.KeyGenerator").getDeclaredMethod("init", int.class, Class.forName("gnu.vm.jgnu.security.SecureRandom"));

						keyPairGeneratorGenerateKeyPair=Class.forName("gnu.vm.jgnu.security.KeyPairGenerator").getDeclaredMethod("generateKeyPair" );
						keyPairGeneratorGetAlgorithm=Class.forName("gnu.vm.jgnu.security.KeyPairGenerator").getDeclaredMethod("getAlgorithm");
						keyPairGeneratorInitRandom=Class.forName("gnu.vm.jgnu.security.KeyPairGenerator").getDeclaredMethod("initialize", int.class, Class.forName("gnu.vm.jgnu.security.SecureRandom"));
						keyPairGeneratorInit=Class.forName("gnu.vm.jgnu.security.KeyPairGenerator").getDeclaredMethod("initialize", int.class);


						macGetAlgorithm=Class.forName("gnu.vm.jgnux.crypto.Mac").getDeclaredMethod("getAlgorithm");
						macGetMacLength=Class.forName("gnu.vm.jgnux.crypto.Mac").getDeclaredMethod("getMacLength");
						macDoFinal=Class.forName("gnu.vm.jgnux.crypto.Mac").getDeclaredMethod("doFinal");
						macGetInstance=Class.forName("gnu.vm.jgnux.crypto.Mac").getDeclaredMethod("getInstance", String.class);
						macDoFinalBytes=Class.forName("gnu.vm.jgnux.crypto.Mac").getDeclaredMethod("doFinal", byte[].class);
						macDoFinalBytesInt=Class.forName("gnu.vm.jgnux.crypto.Mac").getDeclaredMethod("doFinal", byte[].class, int.class);
						macInit=Class.forName("gnu.vm.jgnux.crypto.Mac").getDeclaredMethod("init", Class.forName("gnu.vm.jgnu.security.Key"));
						macReset=Class.forName("gnu.vm.jgnux.crypto.Mac").getDeclaredMethod("reset");
						macUpdateByte=Class.forName("gnu.vm.jgnux.crypto.Mac").getDeclaredMethod("update", byte.class);
						macUpdateBytesIntInt=Class.forName("gnu.vm.jgnux.crypto.Mac").getDeclaredMethod("update", byte[].class, int.class, int.class);
						macUpdateByteBuffer=Class.forName("gnu.vm.jgnux.crypto.Mac").getDeclaredMethod("update", ByteBuffer.class);
						constSecretKeySpec=Class.forName("gnu.vm.jgnux.crypto.spec.SecretKeySpec").getDeclaredConstructor(byte[].class, String.class);
						constSecretKeySpecBytesIntIntString=Class.forName("gnu.vm.jgnux.crypto.spec.SecretKeySpec").getDeclaredConstructor(byte[].class, int.class, int.class, String.class);
						clone=Object.class.getDeclaredMethod("clone");

						keyFactGetInstance=Class.forName("gnu.vm.jgnu.security.KeyFactory").getDeclaredMethod("getInstance", String.class);
						keyFactGeneratePrivate=Class.forName("gnu.vm.jgnu.security.KeyFactory").getDeclaredMethod("generatePrivate", Class.forName("gnu.vm.jgnu.security.spec.KeySpec"));
						keyFactGeneratePublic=Class.forName("gnu.vm.jgnu.security.KeyFactory").getDeclaredMethod("generatePublic", Class.forName("gnu.vm.jgnu.security.spec.KeySpec"));
						constPKCS8EncodedKeySpec=Class.forName("gnu.vm.jgnu.security.spec.PKCS8EncodedKeySpec").getDeclaredConstructor(byte[].class);
						constX509EncodedKeySpec=Class.forName("gnu.vm.jgnu.security.spec.X509EncodedKeySpec").getDeclaredConstructor(byte[].class);

						digestDigest=Class.forName("gnu.vm.jgnu.security.MessageDigest").getDeclaredMethod("digest");
						digestDigestBytes=Class.forName("gnu.vm.jgnu.security.MessageDigest").getDeclaredMethod("digest", byte[].class);
						digestDigestBytesIntInt=Class.forName("gnu.vm.jgnu.security.MessageDigest").getDeclaredMethod("digest", byte[].class, int.class, int.class);
						digestGetAlgorithm=Class.forName("gnu.vm.jgnu.security.MessageDigest").getDeclaredMethod("getAlgorithm");
						digestGetDigestLength=Class.forName("gnu.vm.jgnu.security.MessageDigest").getDeclaredMethod("getDigestLength");
						digestGetProvider=Class.forName("gnu.vm.jgnu.security.MessageDigest").getDeclaredMethod("getProvider");
						digestReset=Class.forName("gnu.vm.jgnu.security.MessageDigest").getDeclaredMethod("reset");
						digestUpdateByte=Class.forName("gnu.vm.jgnu.security.MessageDigest").getDeclaredMethod("update", byte.class);
						digestUpdateBytes=Class.forName("gnu.vm.jgnu.security.MessageDigest").getDeclaredMethod("update", byte[].class);
						digestUpdateBytesIntInt=Class.forName("gnu.vm.jgnu.security.MessageDigest").getDeclaredMethod("update", byte[].class, int.class, int.class);
						digestUpdateByteBuffer=Class.forName("gnu.vm.jgnu.security.MessageDigest").getDeclaredMethod("update", ByteBuffer.class);
						digestGetInstance=Class.forName("gnu.vm.jgnu.security.MessageDigest").getDeclaredMethod("getInstance", String.class);
						providerGetName=Class.forName("gnu.vm.jgnu.security.Provider").getDeclaredMethod("getName");

						secureRandomSetSeed=Class.forName("gnu.vm.jgnu.security.SecureRandom").getDeclaredMethod("setSeed", byte[].class);
						secureRandomNextBytes=Class.forName("gnu.vm.jgnu.security.SecureRandom").getDeclaredMethod("nextBytes", byte[].class);
						secureRandomGenerateSeed=Class.forName("gnu.vm.jgnu.security.SecureRandom").getDeclaredMethod("generateSeed", int.class);

						signatureGetAlgorithm=Class.forName("gnu.vm.jgnu.security.Signature").getDeclaredMethod("getAlgorithm");
						signatureGetProviderName=Class.forName("gnu.vm.jgnu.security.Signature").getDeclaredMethod("getProvider");
						signatureInitSignPriv=Class.forName("gnu.vm.jgnu.security.Signature").getDeclaredMethod("initSign", Class.forName("gnu.vm.jgnu.security.PrivateKey"));
						signatureInitSignPrivRand=Class.forName("gnu.vm.jgnu.security.Signature").getDeclaredMethod("initSign", Class.forName("gnu.vm.jgnu.security.PrivateKey"), Class.forName("gnu.vm.jgnu.security.SecureRandom"));
						signatureInitVerifPub=Class.forName("gnu.vm.jgnu.security.Signature").getDeclaredMethod("initVerify", Class.forName("gnu.vm.jgnu.security.PublicKey"));
						signatureSign=Class.forName("gnu.vm.jgnu.security.Signature").getDeclaredMethod("sign");
						signatureSignBytesIntInt=Class.forName("gnu.vm.jgnu.security.Signature").getDeclaredMethod("sign", byte[].class, int.class, int.class);
						signatureUpdateByte=Class.forName("gnu.vm.jgnu.security.Signature").getDeclaredMethod("update", byte.class);
						signatureUpdateBytes=Class.forName("gnu.vm.jgnu.security.Signature").getDeclaredMethod("update", byte[].class);
						signatureUpdateBytesIntInt=Class.forName("gnu.vm.jgnu.security.Signature").getDeclaredMethod("update", byte[].class, int.class, int.class);
						signatureUpdateByteBuffer=Class.forName("gnu.vm.jgnu.security.Signature").getDeclaredMethod("update", ByteBuffer.class);
						signatureVerifyBytes=Class.forName("gnu.vm.jgnu.security.Signature").getDeclaredMethod("verify", byte[].class);
						signatureVerifyBytesIntInt=Class.forName("gnu.vm.jgnu.security.Signature").getDeclaredMethod("verify", byte[].class, int.class, int.class);




						AccessController.doPrivileged(new PrivilegedAction<Void>() {
							@Override
							public Void run() {
								secureRandomFromSpiConstructor.setAccessible(true);
								macUpdateByteBuffer.setAccessible(true);
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


	static Object decodeGnuPrivateKey(byte[] encodedKey, String algorithm) throws NoSuchAlgorithmException, InvalidKeySpecException {
		checkGnuLoaded();
		try {
			return keyFactGeneratePrivate.invoke(keyFactGetInstance.invoke(null, algorithm),constPKCS8EncodedKeySpec.newInstance((Object)encodedKey));
		} catch (IllegalAccessException | InstantiationException e) {
			throw new IllegalStateException(e);
		} catch (InvocationTargetException e) {
			if (e.getTargetException().getClass().getName().equals("gnu.vm.jgnu.security.NoSuchAlgorithmException"))
				throw new NoSuchAlgorithmException(e.getTargetException());
			if (e.getTargetException().getClass().getName().equals("gnu.vm.jgnu.security.spec.InvalidKeySpecException"))
				throw new InvalidKeySpecException(e.getTargetException());
			throw new IllegalStateException(e);
		}
	}

	static Object macGetInstance(String algorithm) throws NoSuchAlgorithmException {
		checkGnuLoaded();
		try {
			return macGetInstance.invoke(null, algorithm);
		} catch (IllegalAccessException e) {
			throw new IllegalStateException(e);
		} catch (InvocationTargetException e) {
			if (e.getTargetException().getClass().getName().equals("gnu.vm.jgnu.security.NoSuchAlgorithmException"))
				throw new NoSuchAlgorithmException(e.getTargetException());
			throw new IllegalStateException(e);
		}
	}
	static Object secretKeyFactoryGetInstance(String algorithm) throws NoSuchAlgorithmException {
		checkGnuLoaded();
		try {
			return secretKeyFactoryGetInstance.invoke(null, algorithm);
		} catch (IllegalAccessException e) {
			throw new IllegalStateException(e);
		} catch (InvocationTargetException e) {
			if (e.getTargetException().getClass().getName().equals("gnu.vm.jgnu.security.NoSuchAlgorithmException"))
				throw new NoSuchAlgorithmException(e.getTargetException());
			throw new IllegalStateException(e);
		}
	}
	static Object secureRandomGetInstance()  {
		checkGnuLoaded();
		try {
			return constSecureRandom.newInstance();
		} catch (IllegalAccessException | InstantiationException | InvocationTargetException e) {
			throw new IllegalStateException(e);
		}
	}
	static Object secureRandomGetInstance(String algorithm) throws NoSuchAlgorithmException {
		checkGnuLoaded();
		try {
			return secureRandomGetInstance.invoke(null, algorithm);
		} catch (IllegalAccessException e) {
			throw new IllegalStateException(e);
		} catch (InvocationTargetException e) {
			if (e.getTargetException().getClass().getName().equals("gnu.vm.jgnu.security.NoSuchAlgorithmException"))
				throw new NoSuchAlgorithmException(e.getTargetException());
			throw new IllegalStateException(e);
		}
	}
	static Object secretKeyFactoryGenerateSecret(Object secretKeySpec, Object spec)  {
		checkGnuLoaded();
		try {
			return secretKeyFactoryGenerateSecret.invoke(secretKeySpec, spec);
		} catch (IllegalAccessException | InvocationTargetException e) {
			throw new IllegalStateException(e);
		}
	}
	static Object PBEKeySpecGetInstance(char[] password, byte[] salt, int iterationCount, int keyLength) {
		checkGnuLoaded();
		try {
			return constPBEKeySpecCharsBytesIntInt.newInstance(password, salt, iterationCount, keyLength);
		} catch (IllegalAccessException | InstantiationException | InvocationTargetException e) {
			throw new IllegalStateException(e);
		}
	}


	static Object keyGeneratorGetInstance(String algorithm) throws NoSuchAlgorithmException {
		checkGnuLoaded();
		try {
			return keyGeneratorGetInstance.invoke(null, algorithm);
		} catch (IllegalAccessException e) {
			throw new IllegalStateException(e);
		} catch (InvocationTargetException e) {
			if (e.getTargetException().getClass().getName().equals("gnu.vm.jgnu.security.NoSuchAlgorithmException"))
				throw new NoSuchAlgorithmException(e.getTargetException());
			throw new IllegalStateException(e);
		}
	}

	static Object digestGetInstance(String algorithm) throws NoSuchAlgorithmException {
		checkGnuLoaded();
		try {
			return digestGetInstance.invoke(null, algorithm);
		} catch (IllegalAccessException e) {
			throw new IllegalStateException(e);
		} catch (InvocationTargetException e) {
			if (e.getTargetException().getClass().getName().equals("gnu.vm.jgnu.security.NoSuchAlgorithmException"))
				throw new NoSuchAlgorithmException(e.getTargetException());
			throw new IllegalStateException(e);
		}
	}

	static Object secretKeySpecGetInstance(byte[] key, int off, int len, String algorithm) {
		checkGnuLoaded();
		try {
			return constSecretKeySpecBytesIntIntString.newInstance(key, off, len, algorithm);
		} catch (IllegalAccessException | InstantiationException | InvocationTargetException e) {
			throw new IllegalStateException(e);
		}
	}

	static Object secretKeySpecGetInstance(byte[] key, String algorithm) {
		checkGnuLoaded();
		try {
			return constSecretKeySpec.newInstance(key, algorithm);
		} catch (IllegalAccessException | InstantiationException | InvocationTargetException e) {
			throw new IllegalStateException(e);
		}
	}

	static Object decodeGnuPublicKey(byte[] encodedKey, String algorithm) throws NoSuchAlgorithmException, InvalidKeySpecException {
		checkGnuLoaded();
		try {
			return keyFactGeneratePublic.invoke(keyFactGetInstance.invoke(null, algorithm),constX509EncodedKeySpec.newInstance((Object)encodedKey));
		} catch (IllegalAccessException | InstantiationException e) {
			throw new IllegalStateException(e);
		} catch (InvocationTargetException e) {
			if (e.getTargetException().getClass().getName().equals("gnu.vm.jgnu.security.NoSuchAlgorithmException"))
				throw new NoSuchAlgorithmException(e.getTargetException());
			if (e.getTargetException().getClass().getName().equals("gnu.vm.jgnu.security.spec.InvalidKeySpecException"))
				throw new InvalidKeySpecException(e.getTargetException());
			throw new IllegalStateException(e);
		}
	}


	static Object getSignatureAlgorithm(String signatureName) throws NoSuchAlgorithmException {
		checkGnuLoaded();
		try {
			return getSignatureAlgo.invoke(null, signatureName);
		} catch (IllegalAccessException e) {
			throw new IllegalStateException(e);
		} catch (InvocationTargetException e) {
			throw new NoSuchAlgorithmException(e.getTargetException());
		}
	}

	static Object getCipherAlgorithm(String signatureName) throws NoSuchAlgorithmException {
		checkGnuLoaded();
		try {
			return getCihperAlgo.invoke(null, signatureName);
		} catch (IllegalAccessException e) {
			throw new IllegalStateException(e);
		} catch (InvocationTargetException e) {
			throw new NoSuchAlgorithmException(e.getTargetException());
		}
	}

	static void cipherInitWrapMode(Object cipher, Object publicKey, Object random) throws InvalidKeyException {

		try {
			cipherInitIntKeyRandom.invoke(cipher, WRAP_MODE, publicKey, random);
		} catch (IllegalAccessException e) {
			throw new IllegalStateException(e);
		} catch (InvocationTargetException e) {
			throw new InvalidKeyException(e.getTargetException());
		}
	}



	@SuppressWarnings("SameParameterValue")
	static void cipherInit(Object cipher, int mode, SymmetricSecretKey secretKey) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException {

		try {
			cipherInitIntSymKey.invoke(cipher, mode, secretKey.toGnuKey());
		} catch (IllegalAccessException e) {
			throw new IllegalStateException(e);
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

	@SuppressWarnings("SameParameterValue")
	static void cipherInit(Object cipher, int mode, Object publicKey) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException {

		try {
			cipherInitIntKey.invoke(cipher, mode, publicKey);
		} catch (IllegalAccessException e) {
			throw new IllegalStateException(e);
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
	static void cipherInit(Object cipher, int mode, Object publicKey, Object random) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException {

		try {
			cipherInitIntKeyRandom.invoke(cipher, mode, publicKey, random);
		} catch (IllegalAccessException e) {
			throw new IllegalStateException(e);
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
	static Object cipherGetInstance(String name) throws NoSuchAlgorithmException, NoSuchPaddingException {
		checkGnuLoaded();
		try {
			return cipherGetInstance.invoke(null, name);
		} catch (IllegalAccessException e) {
			throw new IllegalStateException(e);
		} catch (InvocationTargetException e) {
			if (e.getTargetException() instanceof IllegalStateException)
				throw (IllegalStateException)e.getTargetException();
			if (e.getTargetException().getClass().getName().equals("gnu.vm.jgnu.security.NoSuchAlgorithmException") )
				throw new NoSuchAlgorithmException(e.getTargetException());
			if (e.getTargetException().getClass().getName().equals("gnu.vm.jgnux.crypto.NoSuchPaddingException") )
				throw new NoSuchPaddingException(e.getTargetException().getMessage());
			throw new IllegalStateException(e.getTargetException());
		}
	}
	static void cipherInit(Object cipher, int mode, Object publicKey, byte[] _iv) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidAlgorithmParameterException {

		try {
			cipherInitIntKeyParamSpec.invoke(cipher, mode, publicKey, IVparamSpec.newInstance((Object)_iv));
		} catch (IllegalAccessException | InstantiationException e) {
			throw new IllegalStateException(e);
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
		try {
			return (byte[])cipherDoFinal.invoke(cipher);
		} catch (IllegalAccessException e) {
			throw new IllegalStateException(e);
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
		try {
			return (int)cipherDoFinalBytesInt.invoke(cipher, _output, _outputOffset);
		} catch (IllegalAccessException e) {
			throw new IllegalStateException(e);
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
		try {
			return (byte[])cipherDoFinalBytesIntInt.invoke(cipher, _input, _inputOffset, _inputLength);
		} catch (IllegalAccessException e) {
			throw new IllegalStateException(e);
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
		try {
			return (int)cipherDoFinalBytesIntIntBytesInt.invoke(cipher, _input, _inputOffset, _inputLength, _output, _outputOffset);
		} catch (IllegalAccessException e) {
			throw new IllegalStateException(e);
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

	static void secureRandomSetSeed(Object secureRandom, byte[] seed)  {
		try {
			secureRandomSetSeed.invoke(secureRandom, (Object)seed);
		} catch (IllegalAccessException e) {
			throw new IllegalStateException(e);
		} catch (InvocationTargetException e) {
			throw new IllegalStateException(e.getTargetException());
		}
	}

	static void secureRandomNextBytes(Object secureRandom, byte[] bytes)  {
		try {
			secureRandomNextBytes.invoke(secureRandom, (Object)bytes);
		} catch (IllegalAccessException e) {
			throw new IllegalStateException(e);
		} catch (InvocationTargetException e) {
			throw new IllegalStateException(e.getTargetException());
		}
	}

	static byte[] secureRandomGenerateSeed(Object secureRandom, int numBytes)  {
		try {
			return (byte[])secureRandomGenerateSeed.invoke(secureRandom, numBytes);
		} catch (IllegalAccessException e) {
			throw new IllegalStateException(e);
		} catch (InvocationTargetException e) {
			throw new IllegalStateException(e.getTargetException());
		}
	}

	static String cipherGetAlgorithm(Object cipher)  {
		try {
			return (String)cipherGetAlgorithm.invoke(cipher);
		} catch (IllegalAccessException e) {
			throw new IllegalStateException(e);
		} catch (InvocationTargetException e) {
			throw new IllegalStateException(e.getTargetException());
		}
	}

	static Object clone(Object o) throws CloneNotSupportedException {
		try {
			return clone.invoke(o);
		} catch (IllegalAccessException e) {
			throw new IllegalStateException(e);
		} catch (InvocationTargetException e) {
			if (e.getTargetException() instanceof CloneNotSupportedException)
				throw (CloneNotSupportedException)e.getTargetException();
			throw new IllegalStateException(e.getTargetException());
		}
	}



	static boolean signatureVerify(Object signature,byte[] _signature, int _offset, int _length) throws SignatureException {
		try {
			return (boolean)signatureVerifyBytesIntInt.invoke(signature,_signature, _offset, _length);
		} catch (IllegalAccessException e) {
			throw new IllegalStateException(e);
		} catch (InvocationTargetException e) {
			if (e.getTargetException().getClass().getName().equals("gnu.vm.jgnu.security.SignatureException"))
				throw new SignatureException(e.getTargetException());
			throw new IllegalStateException(e.getTargetException());
		}
	}

	static boolean signatureVerify(Object signature,byte[] _signature) throws SignatureException {
		try {
			return (boolean)signatureVerifyBytes.invoke(signature,(Object)_signature);
		} catch (IllegalAccessException e) {
			throw new IllegalStateException(e);
		} catch (InvocationTargetException e) {
			if (e.getTargetException().getClass().getName().equals("gnu.vm.jgnu.security.SignatureException"))
				throw new SignatureException(e.getTargetException());
			throw new IllegalStateException(e.getTargetException());
		}
	}

	static void signatureUpdate(Object signature,ByteBuffer _input) throws SignatureException {
		try {
			signatureUpdateByteBuffer.invoke(signature,_input);
		} catch (IllegalAccessException e) {
			throw new IllegalStateException(e);
		} catch (InvocationTargetException e) {
			if (e.getTargetException().getClass().getName().equals("gnu.vm.jgnu.security.SignatureException"))
				throw new SignatureException(e.getTargetException());
			throw new IllegalStateException(e.getTargetException());
		}
	}

	static void signatureUpdate(Object signature, byte[] _data, int _off, int _len) throws SignatureException {
		try {
			signatureUpdateBytesIntInt.invoke(signature,_data, _off, _len);
		} catch (IllegalAccessException e) {
			throw new IllegalStateException(e);
		} catch (InvocationTargetException e) {
			if (e.getTargetException().getClass().getName().equals("gnu.vm.jgnu.security.SignatureException"))
				throw new SignatureException(e.getTargetException());
			throw new IllegalStateException(e.getTargetException());
		}
	}

	static void signatureUpdate(Object signature, byte[] _b) throws SignatureException {
		try {
			signatureUpdateBytes.invoke(signature, (Object)_b);
		} catch (IllegalAccessException e) {
			throw new IllegalStateException(e);
		} catch (InvocationTargetException e) {
			if (e.getTargetException().getClass().getName().equals("gnu.vm.jgnu.security.SignatureException"))
				throw new SignatureException(e.getTargetException());
			throw new IllegalStateException(e.getTargetException());
		}
	}

	static void signatureUpdate(Object signature, byte _b) throws SignatureException {
		try {
			signatureUpdateByte.invoke(signature, _b);
		} catch (IllegalAccessException e) {
			throw new IllegalStateException(e);
		} catch (InvocationTargetException e) {
			if (e.getTargetException().getClass().getName().equals("gnu.vm.jgnu.security.SignatureException"))
				throw new SignatureException(e.getTargetException());
			throw new IllegalStateException(e.getTargetException());
		}
	}

	static int signatureSign(Object signature, byte[] _outbuf, int _offset, int _len) throws SignatureException {
		try {
			return (int)signatureSignBytesIntInt.invoke(signature, _outbuf, _offset, _len);
		} catch (IllegalAccessException e) {
			throw new IllegalStateException(e);
		} catch (InvocationTargetException e) {
			if (e.getTargetException().getClass().getName().equals("gnu.vm.jgnu.security.SignatureException"))
				throw new SignatureException(e.getTargetException());
			throw new IllegalStateException(e.getTargetException());
		}
	}

	static byte[] signatureSign(Object signature) throws SignatureException {
		try {
			return (byte[])signatureSign.invoke(signature);
		} catch (IllegalAccessException e) {
			throw new IllegalStateException(e);
		} catch (InvocationTargetException e) {
			if (e.getTargetException().getClass().getName().equals("gnu.vm.jgnu.security.SignatureException"))
				throw new SignatureException(e.getTargetException());
			throw new IllegalStateException(e.getTargetException());
		}
	}

	static void signatureInitVerify(Object signature, ASymmetricPublicKey _publicKey) throws InvalidKeySpecException, NoSuchAlgorithmException, InvalidKeyException {
		try {
			signatureInitVerifPub.invoke(signature, _publicKey.toGnuKey());
		} catch (IllegalAccessException e) {
			throw new IllegalStateException(e);
		} catch (InvocationTargetException e) {
			if (e.getTargetException().getClass().getName().equals("gnu.vm.jgnu.security.InvalidKeyException"))
				throw new InvalidKeyException(e.getTargetException());
			throw new IllegalStateException(e.getTargetException());
		}
	}

	static void signatureInitSign(Object signature, ASymmetricPrivateKey _privateKey, AbstractSecureRandom _random) throws InvalidKeySpecException, NoSuchAlgorithmException, InvalidKeyException {
		try {
			signatureInitSignPrivRand.invoke(signature, _privateKey.toGnuKey(), _random.getGnuSecureRandom());
		} catch (IllegalAccessException e) {
			throw new IllegalStateException(e);
		} catch (InvocationTargetException e) {
			if (e.getTargetException().getClass().getName().equals("gnu.vm.jgnu.security.InvalidKeyException"))
				throw new InvalidKeyException(e.getTargetException());
			throw new IllegalStateException(e.getTargetException());
		}
	}
	static void signatureInitSign(Object signature, ASymmetricPrivateKey _privateKey) throws InvalidKeySpecException, NoSuchAlgorithmException, InvalidKeyException {
		try {
			signatureInitSignPriv.invoke(signature, _privateKey.toGnuKey());
		} catch (IllegalAccessException e) {
			throw new IllegalStateException(e);
		} catch (InvocationTargetException e) {
			if (e.getTargetException().getClass().getName().equals("gnu.vm.jgnu.security.InvalidKeyException"))
				throw new InvalidKeyException(e.getTargetException());
			throw new IllegalStateException(e.getTargetException());
		}
	}

	static String signatureGetAlgorithm(Object signature) {
		try {
			return (String)signatureGetAlgorithm.invoke(signature);
		} catch (IllegalAccessException e) {
			throw new IllegalStateException(e);
		} catch (InvocationTargetException e) {
			throw new IllegalStateException(e.getTargetException());
		}
	}

	static String signatureGetProvider(Object signature) {
		try {
			return (String)providerGetName.invoke(signatureGetProviderName.invoke(signature));
		} catch (IllegalAccessException e) {
			throw new IllegalStateException(e);
		} catch (InvocationTargetException e) {
			throw new IllegalStateException(e.getTargetException());
		}
	}

	static void macReset(Object cipher) {
		try {
			macReset.invoke(cipher);
		} catch (IllegalAccessException e) {
			throw new IllegalStateException(e);
		} catch (InvocationTargetException e) {
			throw new IllegalStateException(e.getTargetException());
		}
	}
	static int macGetLengthByes(Object cipher) {
		try {
			return (int)macGetMacLength.invoke(cipher);
		} catch (IllegalAccessException e) {
			throw new IllegalStateException(e);
		} catch (InvocationTargetException e) {
			throw new IllegalStateException(e.getTargetException());
		}
	}

	static void digestUpdate(Object digest, ByteBuffer _input) {
		try {
			digestUpdateByteBuffer.invoke(digest, _input);
		} catch (IllegalAccessException e) {
			throw new IllegalStateException(e);
		} catch (InvocationTargetException e) {
			throw new IllegalStateException(e.getTargetException());
		}
	}

	static void digestUpdate(Object digest, byte[] _input, int _offset, int _len) {
		try {
			digestUpdateBytesIntInt.invoke(digest, _input, _offset, _len);
		} catch (IllegalAccessException e) {
			throw new IllegalStateException(e);
		} catch (InvocationTargetException e) {
			throw new IllegalStateException(e.getTargetException());
		}
	}

	static void digestUpdate(Object digest, byte[] _input) {
		try {
			digestUpdateBytes.invoke(digest, (Object) _input);
		} catch (IllegalAccessException e) {
			throw new IllegalStateException(e);
		} catch (InvocationTargetException e) {
			throw new IllegalStateException(e.getTargetException());
		}
	}

	static void digestUpdate(Object digest, byte _input) {
		try {
			digestUpdateByte.invoke(digest, _input);
		} catch (IllegalAccessException e) {
			throw new IllegalStateException(e);
		} catch (InvocationTargetException e) {
			throw new IllegalStateException(e.getTargetException());
		}
	}

	static void digestReset(Object digest) {
		try {
			digestReset.invoke(digest);
		} catch (IllegalAccessException e) {
			throw new IllegalStateException(e);
		} catch (InvocationTargetException e) {
			throw new IllegalStateException(e.getTargetException());
		}
	}
	static String digestGetProviderName(Object digest) {
		try {
			return (String)providerGetName.invoke(digestGetProvider.invoke(digest));
		} catch (IllegalAccessException e) {
			throw new IllegalStateException(e);
		} catch (InvocationTargetException e) {
			throw new IllegalStateException(e.getTargetException());
		}
	}

	static int digestGetLength(Object digest) {
		try {
			return (int)digestGetDigestLength.invoke(digest);
		} catch (IllegalAccessException e) {
			throw new IllegalStateException(e);
		} catch (InvocationTargetException e) {
			throw new IllegalStateException(e.getTargetException());
		}
	}

	static int digestDigest(Object digest,byte[] _buf, int _offset, int _len) throws DigestException {
		try {
			return (int)digestDigestBytesIntInt.invoke(digest, _buf, _offset, _len);
		} catch (IllegalAccessException e) {
			throw new IllegalStateException(e);
		} catch (InvocationTargetException e) {
			if (e.getTargetException().getClass().getName().equals("gnu.vm.jgnu.security.DigestException"))
				throw new DigestException(e);
			throw new IllegalStateException(e.getTargetException());
		}
	}

	static byte[] digestDigest(Object digest, byte[] _input) {
		try {
			return (byte[])digestDigestBytes.invoke(digest, (Object)_input);
		} catch (IllegalAccessException e) {
			throw new IllegalStateException(e);
		} catch (InvocationTargetException e) {
			throw new IllegalStateException(e.getTargetException());
		}
	}

	static String digestGetAlgorithm(Object digest) {
		try {
			return (String)digestGetAlgorithm.invoke(digest);
		} catch (IllegalAccessException e) {
			throw new IllegalStateException(e);
		} catch (InvocationTargetException e) {
			throw new IllegalStateException(e.getTargetException());
		}
	}
	static byte[] digestDigest(Object digest) {
		try {
			return (byte[])digestDigest.invoke(digest);
		} catch (IllegalAccessException e) {
			throw new IllegalStateException(e);
		} catch (InvocationTargetException e) {
			throw new IllegalStateException(e.getTargetException());
		}
	}


	static String macGetAlgorithm(Object cipher) {
		try {
			return (String)macGetAlgorithm.invoke(cipher);
		} catch (IllegalAccessException e) {
			throw new IllegalStateException(e);
		} catch (InvocationTargetException e) {
			throw new IllegalStateException(e.getTargetException());
		}
	}
	static byte[] macDoFinal(Object cipher) throws IllegalStateException {
		try {
			return (byte[])macDoFinal.invoke(cipher);
		} catch (IllegalAccessException e) {
			throw new IllegalStateException(e);
		} catch (InvocationTargetException e) {
			if (e.getTargetException() instanceof IllegalStateException)
				throw (IllegalStateException)e.getTargetException();
			throw new IllegalStateException(e.getTargetException());
		}
	}
	static byte[] macDoFinal(Object cipher, byte[] _input) throws IllegalStateException {
		try {
			return (byte[])macDoFinalBytes.invoke(cipher, (Object)_input);
		} catch (IllegalAccessException e) {
			throw new IllegalStateException(e);
		} catch (InvocationTargetException e) {
			if (e.getTargetException() instanceof IllegalStateException)
				throw (IllegalStateException)e.getTargetException();
			throw new IllegalStateException(e.getTargetException());
		}
	}
	static void macDoFinal(Object cipher, byte[] _output, int _outOffset) throws IllegalStateException, ShortBufferException {
		try {
			macDoFinalBytesInt.invoke(cipher, _output, _outOffset);
		} catch (IllegalAccessException e) {
			throw new IllegalStateException(e);
		} catch (InvocationTargetException e) {
			if (e.getTargetException() instanceof IllegalStateException)
				throw (IllegalStateException)e.getTargetException();
			if (e.getTargetException().getClass().getName().equals("gnu.vm.jgnux.crypto.ShortBufferException") )
				throw new ShortBufferException(e.getTargetException().getMessage());
			throw new IllegalStateException(e.getTargetException());
		}
	}
	static void macUpdate(Object cipher, byte _input) throws IllegalStateException {
		try {
			macUpdateByte.invoke(cipher, _input);
		} catch (IllegalAccessException e) {
			throw new IllegalStateException(e);
		} catch (InvocationTargetException e) {
			if (e.getTargetException() instanceof IllegalStateException)
				throw (IllegalStateException)e.getTargetException();
			throw new IllegalStateException(e.getTargetException());
		}
	}
	static void macUpdate(Object cipher, byte[] _input, int _offset, int _length) throws IllegalStateException {
		try {
			macUpdateBytesIntInt.invoke(cipher, _input, _offset, _length);
		} catch (IllegalAccessException e) {
			throw new IllegalStateException(e);
		} catch (InvocationTargetException e) {
			if (e.getTargetException() instanceof IllegalStateException)
				throw (IllegalStateException)e.getTargetException();
			throw new IllegalStateException(e.getTargetException());
		}
	}
	static void macUpdate(Object cipher, ByteBuffer _buffer) {
		try {
			macUpdateByteBuffer.invoke(cipher, _buffer);
		} catch (IllegalAccessException e) {
			throw new IllegalStateException(e);
		} catch (InvocationTargetException e) {
			if (e.getTargetException() instanceof IllegalStateException)
				throw (IllegalStateException)e.getTargetException();
			throw new IllegalStateException(e.getTargetException());
		}
	}
	static void macInit(Object cipher, Key key) throws InvalidKeySpecException, NoSuchAlgorithmException, InvalidKeyException {
		try {
			macInit.invoke(cipher, constSecretKeySpec.newInstance(keyGetEncoded(key.toGnuKey()), macGetAlgorithm(cipher)));
		} catch (IllegalAccessException | InstantiationException e) {
			throw new IllegalStateException(e);
		} catch (InvocationTargetException e) {
			if (e.getTargetException() instanceof IllegalStateException)
				throw (IllegalStateException)e.getTargetException();
			if (e.getTargetException().getClass().getName().equals("gnu.vm.jgnu.security.InvalidKeyException") )
				throw new InvalidKeyException(e.getTargetException());
			throw new IllegalStateException(e.getTargetException());
		}
	}
	static String keyGeneratorGetAlgorithm(Object keyGenerator)  {
		try {
			return (String)keyGeneratorGetAlgorithm.invoke(keyGenerator);
		} catch (IllegalAccessException e) {
			throw new IllegalStateException(e);
		} catch (InvocationTargetException e) {
			throw new IllegalStateException(e.getTargetException());
		}
	}
	static String keyGeneratorGetProvider(Object keyGenerator)  {
		try {
			return (String) providerGetName.invoke(keyGeneratorGetProvider.invoke(keyGenerator));
		} catch (IllegalAccessException e) {
			throw new IllegalStateException(e);
		} catch (InvocationTargetException e) {
			throw new IllegalStateException(e.getTargetException());
		}
	}
	static Object keyGeneratorGeneratorKey(Object keyGenerator)  {
		try {
			return keyGeneratorGenerateKey.invoke(keyGenerator);
		} catch (IllegalAccessException e) {
			throw new IllegalStateException(e);
		} catch (InvocationTargetException e) {
			throw new IllegalStateException(e.getTargetException());
		}
	}
	static void keyGeneratorInit(Object keyGenerator, short _keySize, AbstractSecureRandom _random)  {
		try {
			keyGeneratorInit.invoke(keyGenerator, _keySize, _random.getGnuSecureRandom());
		} catch (IllegalAccessException e) {
			throw new IllegalStateException(e);
		} catch (InvocationTargetException e) {
			throw new IllegalStateException(e.getTargetException());
		}
	}



	static String keyPairGeneratorGetAlgorithm(Object keyGenerator)  {
		try {
			return (String)keyPairGeneratorGetAlgorithm.invoke(keyGenerator);
		} catch (IllegalAccessException e) {
			throw new IllegalStateException(e);
		} catch (InvocationTargetException e) {
			throw new IllegalStateException(e.getTargetException());
		}
	}
	static Object keyPairGeneratorGeneratorKeyPair(Object keyGenerator)  {
		try {
			return  keyPairGeneratorGenerateKeyPair.invoke(keyGenerator);
		} catch (IllegalAccessException e) {
			throw new IllegalStateException(e);
		} catch (InvocationTargetException e) {
			throw new IllegalStateException(e.getTargetException());
		}
	}
	static void keyPairGeneratorInit(Object keyGenerator, short _keySize, AbstractSecureRandom _random)  {
		try {
			keyPairGeneratorInitRandom.invoke(keyGenerator, _keySize, _random.getGnuSecureRandom());
		} catch (IllegalAccessException e) {
			throw new IllegalStateException(e);
		} catch (InvocationTargetException e) {
			throw new IllegalStateException(e.getTargetException());
		}
	}
	static void keyPairGeneratorInit(Object keyGenerator, short _keySize)  {
		try {
			keyPairGeneratorInit.invoke(keyGenerator, _keySize);
		} catch (IllegalAccessException e) {
			throw new IllegalStateException(e);
		} catch (InvocationTargetException e) {
			throw new IllegalStateException(e.getTargetException());
		}
	}
	static int cipherGetBlockSize(Object cipher)  {
		try {
			return (int)cipherGetBlockSize.invoke(cipher);
		} catch (IllegalAccessException e) {
			throw new IllegalStateException(e);
		} catch (InvocationTargetException e) {
			throw new IllegalStateException(e.getTargetException());
		}
	}

	static byte[] cipherGetIV(Object cipher)  {

		try {
			return (byte[])cipherGetIv.invoke(cipher);
		} catch (IllegalAccessException e) {
			throw new IllegalStateException(e);
		} catch (InvocationTargetException e) {
			throw new IllegalStateException(e.getTargetException());
		}
	}
	static int cipherGetOutputSize(Object cipher, int _inputLength) throws IllegalStateException {

		try {
			return (int)cipherGetOutputSize.invoke(cipher, _inputLength);
		} catch (IllegalAccessException e) {
			throw new IllegalStateException(e);
		} catch (InvocationTargetException e) {
			if (e.getTargetException() instanceof IllegalStateException)
				throw (IllegalStateException)e.getTargetException();
			throw new IllegalStateException(e.getTargetException());
		}
	}

	static byte[] cipherUpdate(Object cipher,byte[] _input, int _inputOffset, int _inputLength) throws IllegalStateException {
		try {
			return (byte[])cipherUpdateBytesIntInt.invoke(cipher, _input, _inputOffset, _inputLength);
		} catch (IllegalAccessException e) {
			throw new IllegalStateException(e);
		} catch (InvocationTargetException e) {
			if (e.getTargetException() instanceof IllegalStateException)
				throw (IllegalStateException)e.getTargetException();
			throw new IllegalStateException(e.getTargetException());
		}
	}
	static int cipherUpdate(Object cipher,byte[] _input, int _inputOffset, int _inputLength, byte[] _output, int _outputOffset) throws IllegalStateException, ShortBufferException {
		try {
			return (int)cipherUpdateBytesIntIntBytesInt.invoke(cipher, _input, _inputOffset, _inputLength, _output, _outputOffset);
		} catch (IllegalAccessException e) {
			throw new IllegalStateException(e);
		} catch (InvocationTargetException e) {
			if (e.getTargetException() instanceof IllegalStateException)
				throw (IllegalStateException)e.getTargetException();
			if (e.getTargetException().getClass().getName().equals("gnu.vm.jgnux.crypto.ShortBufferException") )
				throw new ShortBufferException(e.getTargetException().getMessage());
			throw new IllegalStateException(e.getTargetException());
		}
	}
	static InputStream cipherGetCipherInputStream(Object cipher,InputStream in)  {
		try {
			return (InputStream)constCipherInputStream.newInstance(in, cipher);
		} catch (IllegalAccessException | InstantiationException e) {
			throw new IllegalStateException(e);
		} catch (InvocationTargetException e) {
			throw new IllegalStateException(e.getTargetException());
		}
	}
	static OutputStream cipherGetCipherOutputStream(Object cipher,OutputStream out)  {
		try {
			return (OutputStream)consCipherOutputStream.newInstance(out, cipher);
		} catch (IllegalAccessException | InstantiationException e) {
			throw new IllegalStateException(e);
		} catch (InvocationTargetException e) {
			throw new IllegalStateException(e.getTargetException());
		}
	}

	static void cipherInitUnwrapMode(Object cipher, Object privateKey) throws InvalidKeyException {
		try {
			cipherInitUnwrap.invoke(cipher, UNWRAP_MODE, privateKey);
		} catch (IllegalAccessException e) {
			throw new IllegalStateException(e);
		} catch (InvocationTargetException e) {
			throw new InvalidKeyException(e.getTargetException());
		}
	}


	static byte[] cipherWrap(Object cipher, Object keyToWrap) throws IllegalStateException, IllegalBlockSizeException, InvalidKeyException {
		try {
			return (byte[])cipherWrap.invoke(cipher, keyToWrap);
		} catch (IllegalAccessException e) {
			throw new IllegalStateException(e);
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
			throw new IllegalStateException(e);
		}
	}

	static Object cipherUnwrap(Object cipher, byte[] keyToUnwrap, String algorithmName) throws IllegalStateException, InvalidKeyException, NoSuchAlgorithmException  {
		try {
			return cipherUnwrapByteStringInt.invoke(cipher, keyToUnwrap, algorithmName, SECRET_KEY);
		} catch (IllegalAccessException e) {
			throw new IllegalStateException(e);
		} catch (InvocationTargetException e) {
			if (e.getTargetException() instanceof IllegalStateException)
				throw (IllegalStateException)e.getTargetException();
			if (e.getTargetException() instanceof InvalidKeyException)
				throw (InvalidKeyException)e.getTargetException();
			else if (e.getTargetException().getClass().getName().equals("gnu.vm.jgnux.crypto.InvalidKeyException"))
				throw new InvalidKeyException(e.getTargetException());
			else if (e.getTargetException().getClass().getName().equals("gnu.vm.jgnu.security.NoSuchAlgorithmException"))
				throw new NoSuchAlgorithmException(e.getTargetException());
			throw new IllegalStateException(e);
		}
	}


	static Object getPublicKey(Object keyPair) {
		checkGnuLoaded();
		try {
			return getPublicKey.invoke(keyPair);
		} catch (IllegalAccessException | InvocationTargetException e) {
			throw new IllegalStateException(e);
		}
	}

	static Object getPrivateKey(Object keyPair) {
		checkGnuLoaded();
		try {
			return getPrivateKey.invoke(keyPair);
		} catch (IllegalAccessException | InvocationTargetException e) {
			throw new IllegalStateException(e);
		}
	}
	static byte[] keyGetEncoded(Object key) {
		checkGnuLoaded();
		try {
			return (byte[])getEncoded.invoke(key);
		} catch (IllegalAccessException | InvocationTargetException e) {
			throw new IllegalStateException(e);
		}
	}

	static Object getKeyPairInstance(Object publicKey, Object privateKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
		checkGnuLoaded();
		try {
			return keyPairConstructorPublicPrivate.newInstance(publicKey, privateKey);
		} catch (InstantiationException | IllegalAccessException e) {
			throw new IllegalStateException(e);
		} catch (InvocationTargetException e) {
			if (e.getTargetException().getClass().getName().equals("gnu.vm.jgnu.security.NoSuchAlgorithmException"))
				throw new NoSuchAlgorithmException(e.getTargetException());
			else if (e.getTargetException().getClass().getName().equals("gnu.vm.jgnu.security.spec.InvalidKeySpecException"))
				throw new InvalidKeySpecException(e.getTargetException());
			throw new IllegalStateException(e);
		}
	}

	static Object getKeyPairGenerator(String algoName) throws NoSuchAlgorithmException {
		checkGnuLoaded();
		try {
			return keyPairGeneratorConstructorString.newInstance(algoName);
		} catch (InstantiationException | IllegalAccessException e) {
			throw new IllegalStateException(e);
		} catch (InvocationTargetException e) {
			if (e.getTargetException().getClass().getName().equals("gnu.vm.jgnu.security.NoSuchAlgorithmException"))
				throw new NoSuchAlgorithmException(e.getTargetException());
			throw new IllegalStateException(e);
		}
	}

	private static class IHForGnuInterface implements InvocationHandler
	{
		final AbstractSecureRandom.AbstractSecureRandomSpi secureRandom;
		boolean initialized=false;

		public IHForGnuInterface(AbstractSecureRandom.AbstractSecureRandomSpi secureRandom) {
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
			IHForGnuInterface ihForGnuInterface =new IHForGnuInterface(secureRandom);
			Object o= Proxy.newProxyInstance(c.getClassLoader(),
					new Class[]{c},
					ihForGnuInterface);
			o=secureRandomFromSpiConstructor.newInstance(o, null);
			ihForGnuInterface.initialized=true;
			return o;
		} catch (ClassNotFoundException | InstantiationException | IllegalAccessException | InvocationTargetException e) {
			throw new IllegalStateException(e);
		}
	}



}

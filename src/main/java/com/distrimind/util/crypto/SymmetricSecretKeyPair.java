package com.distrimind.util.crypto;
/*
Copyright or © or Copr. Jason Mahdjoub (01/04/2013)

jason.mahdjoub@distri-mind.fr

This software (Object Oriented Database (OOD)) is a computer program 
whose purpose is to manage a local database with the object paradigm 
and the java language

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

import com.distrimind.util.Bits;
import com.distrimind.util.Cleanable;
import com.distrimind.util.data_buffers.WrappedSecretData;
import com.distrimind.util.data_buffers.WrappedSecretString;

import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Objects;

/**
 * @author Jason Mahdjoub
 * @version 1.1
 * @since Utils 4.7.0
 */
public class SymmetricSecretKeyPair extends AbstractKey implements ISecretDecentralizedValue{
	private static final class Finalizer extends Cleaner
	{
		private SymmetricSecretKey secretKeyForEncryption;
		private SymmetricSecretKey secretKeyForSignature;

		private Finalizer(Cleanable cleanable) {
			super(cleanable);
		}

		@Override
		protected void performCleanup() {
			secretKeyForEncryption = null;
			secretKeyForSignature = null;
		}
	}
	private final Finalizer finalizer;
	public SymmetricSecretKeyPair(SymmetricSecretKey secretKeyForEncryption, SymmetricSecretKey secretKeyForSignature) {
		if (secretKeyForEncryption==null)
			throw new NullPointerException();
		if (secretKeyForSignature==null)
			throw new NullPointerException();
		if (!secretKeyForEncryption.useEncryptionAlgorithm())
			throw new IllegalArgumentException();
		if (!secretKeyForSignature.useAuthenticatedSignatureAlgorithm())
			throw new IllegalArgumentException();
		finalizer=new Finalizer(this);
		this.finalizer.secretKeyForEncryption = secretKeyForEncryption;
		this.finalizer.secretKeyForSignature = secretKeyForSignature;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;
		SymmetricSecretKeyPair that = (SymmetricSecretKeyPair) o;
		boolean b=finalizer.secretKeyForEncryption.equals(that.finalizer.secretKeyForEncryption);
		b=finalizer.secretKeyForSignature.equals(that.finalizer.secretKeyForSignature) && b;
		return b;
	}

	@Override
	public int hashCode() {
		return Objects.hash(finalizer.secretKeyForEncryption, finalizer.secretKeyForSignature);
	}

	public SymmetricSecretKey getSecretKeyForEncryption() {
		return finalizer.secretKeyForEncryption;
	}

	public SymmetricSecretKey getSecretKeyForSignature() {
		return finalizer.secretKeyForSignature;
	}

	@Override
	@Deprecated
	public Object toGnuKey()  {
		throw new IllegalAccessError();
	}

	@Override
	@Deprecated
	public Key toJavaNativeKey() {
		throw new IllegalAccessError();
	}

	@Override
	@Deprecated
	public com.distrimind.bcfips.crypto.Key toBouncyCastleKey() {
		throw new IllegalAccessError();
	}


	@Override
	public WrappedSecretData encode()
	{
		WrappedSecretData encodedSecretKeyForEncryption=finalizer.secretKeyForEncryption.encode();
		WrappedSecretData encodedSecretKeyForSignature=finalizer.secretKeyForSignature.encode();
		byte[] tab = new byte[2+encodedSecretKeyForEncryption.getBytes().length+encodedSecretKeyForSignature.getBytes().length];
		tab[0]=AbstractKey.IS_XDH_KEY;
		if (encodedSecretKeyForEncryption.getBytes().length>255)
			throw new IllegalAccessError();
		tab[1]=(byte)encodedSecretKeyForEncryption.getBytes().length;
		System.arraycopy(encodedSecretKeyForEncryption.getBytes(), 0, tab, 2, encodedSecretKeyForEncryption.getBytes().length);
		System.arraycopy(encodedSecretKeyForSignature.getBytes(), 0, tab, encodedSecretKeyForEncryption.getBytes().length+2, encodedSecretKeyForSignature.getBytes().length);
		return new WrappedSecretData(tab);

	}

	@Override
	public WrappedSecretString encodeString() {
		return new WrappedSecretString(encode());
	}

	public SymmetricSecretKeyPair getHashedSecretKeyPair(MessageDigestType messageDigestType, long customApplicationCode) throws NoSuchProviderException, NoSuchAlgorithmException {
		byte[] tab=new byte[8];
		Bits.putLong(tab, 0, customApplicationCode);
		return getHashedSecretKeyPair(messageDigestType, tab);
	}
	public SymmetricSecretKeyPair getHashedSecretKeyPair(MessageDigestType messageDigestType) throws NoSuchProviderException, NoSuchAlgorithmException {
		return getHashedSecretKeyPair(messageDigestType, null);
	}
	public SymmetricSecretKeyPair getHashedSecretKeyPair(MessageDigestType messageDigestType, byte[] customApplicationCode) throws NoSuchProviderException, NoSuchAlgorithmException {
		return new SymmetricSecretKeyPair(finalizer.secretKeyForEncryption.getHashedSecretKey(messageDigestType, customApplicationCode), finalizer.secretKeyForSignature.getHashedSecretKey(messageDigestType, customApplicationCode));
	}



	@Override
	public WrappedSecretData getKeyBytes() {
		return encode();
	}

	@Override
	public boolean isPostQuantumKey() {
		return finalizer.secretKeyForEncryption.isPostQuantumKey() && finalizer.secretKeyForSignature.isPostQuantumKey();
	}

	@Override
	public boolean useEncryptionAlgorithm() {
		return true;
	}

	@Override
	public boolean useAuthenticatedSignatureAlgorithm() {
		return true;
	}

	@Override
	public String getShortClassName()
	{
		return "secretKeys";
	}
}

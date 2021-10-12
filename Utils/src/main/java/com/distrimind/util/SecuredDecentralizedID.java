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
package com.distrimind.util;

import com.distrimind.util.crypto.AbstractMessageDigest;
import com.distrimind.util.crypto.AbstractSecureRandom;
import com.distrimind.util.crypto.MessageDigestType;
import com.distrimind.util.data_buffers.WrappedSecretData;
import com.distrimind.util.data_buffers.WrappedString;
import com.distrimind.util.sizeof.ObjectSizer;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicReference;


/**
 * This class represents a unique identifier. Uniqueness is guaranteed over the
 * network.
 * 
 * @author Jason Mahdjoub
 * @version 2.0
 * @since Utils 1.3
 * 
 */
public class SecuredDecentralizedID extends AbstractDecentralizedID {

	/**
	 * 
	 */
	private static final long serialVersionUID = 4728193961114275589L;

	public static final int MAX_SECURED_DECENTRALIZED_ID_LENGTH=AbstractDecentralizedID.PRIVATE_MAX_SECURED_DECENTRALIZED_ID_SIZE_IN_BYTES;

	private static final AtomicReference<AbstractMessageDigest> message_digest = new AtomicReference<>(null);

	public static final MessageDigestType DEFAULT_MESSAGE_DIGEST_TYPE = MessageDigestType.BC_FIPS_SHA3_256;

	static final String ToStringHead = "SecuredDecentralizedID";

	private static int computeHashCode(long[] idLongs) {
		return Arrays.hashCode(idLongs);
	}

	private static AbstractMessageDigest getDefaultMessageDigestInstance() throws NoSuchAlgorithmException, NoSuchProviderException {
		AbstractMessageDigest md = message_digest.get();
		if (md == null) {
			synchronized (message_digest) {
				md = message_digest.get();
				if (md == null) {
					md = DEFAULT_MESSAGE_DIGEST_TYPE.getMessageDigestInstance();
					message_digest.set(md);
				}
			}
		}
		return md;
	}
	public static SecuredDecentralizedID valueOf(String value) throws InvalidEncodedValue {
		return valueOf(new WrappedString(value));

	}
	public static SecuredDecentralizedID valueOf(WrappedString value) throws InvalidEncodedValue {
		AbstractDecentralizedID res = AbstractDecentralizedID.valueOf(value);
		if (res instanceof SecuredDecentralizedID) {
			return (SecuredDecentralizedID) res;
		} else
			throw new IllegalArgumentException("Invalid format : " + value);
	}

	private final long[] idLongs;

	private transient int hashCode;

	public SecuredDecentralizedID(AbstractDecentralizedIDGenerator generator, AbstractSecureRandom rand)
			throws NoSuchAlgorithmException, NoSuchProviderException {
		this(getDefaultMessageDigestInstance(), generator, rand);
	}

	@SuppressWarnings("SynchronizationOnLocalVariableOrMethodParameter")
	public SecuredDecentralizedID(AbstractMessageDigest messageDigest, AbstractDecentralizedIDGenerator generator,
								  AbstractSecureRandom rand) {
		if (messageDigest == null)
			throw new NullPointerException("messageDigest");
		if (generator == null)
			throw new NullPointerException("generator");
		if (rand == null)
			throw new NullPointerException("rand");
		synchronized (messageDigest) {

			long v = 1L;
			final int sizeLong = ObjectSizer.sizeOf(v);
			byte[] idBytes = new byte[sizeLong * 2];
			Bits.putLong(idBytes, 0, generator.getWorkerIDAndSequence());
			Bits.putLong(idBytes, sizeLong, generator.getTimeStamp());

			byte[] salt ;
			int size = Math.max(messageDigest.getDigestLengthInBytes(), idBytes.length) - idBytes.length;
			salt = new byte[size];

			rand.nextBytes(salt);
			messageDigest.update(idBytes);
			messageDigest.update(salt);

			byte[] id = messageDigest.digest();
			size = id.length / sizeLong;
			int mod = id.length % sizeLong;
			if (mod > 0)
				++size;
			idLongs = new long[size];
			for (int i = 0; (((i + 1) * sizeLong) - 1) < id.length; i++) {
				idLongs[i] = Bits.getLong(id, i * sizeLong);
			}
			if (mod > 0) {
				idBytes = new byte[sizeLong];
				System.arraycopy(id, size, idBytes, 0, mod);
				for (int i = mod; i < sizeLong; i++) {
					idBytes[i] = 0;
				}
				idLongs[idLongs.length - 1] = Bits.getLong(idBytes, 0);
			}
			hashCode = computeHashCode(idLongs);
		}
	}

	SecuredDecentralizedID(long[] idLongs) {
		if (idLongs == null)
			throw new NullPointerException("idLongs");
		if (idLongs.length == 0)
			throw new IllegalArgumentException("idLongs.length");
		this.idLongs = idLongs;
		this.hashCode = computeHashCode(idLongs);
	}

	public SecuredDecentralizedID(MessageDigestType messageDigestType, AbstractDecentralizedIDGenerator generator,
			AbstractSecureRandom rand) throws NoSuchAlgorithmException, NoSuchProviderException {
		this(messageDigestType.getMessageDigestInstance(), generator, rand);
	}

	@Override
	public boolean equals(Object _obj) {
		if (_obj == null)
			return false;
		if (_obj == this)
			return true;
		if (_obj instanceof SecuredDecentralizedID) {
			SecuredDecentralizedID sid = (SecuredDecentralizedID) _obj;
			if (sid.idLongs == null)
				return false;
			if (sid.idLongs.length != idLongs.length)
				return false;
			for (int i = 0; i < idLongs.length; i++) {
				if (idLongs[i] != sid.idLongs[i])
					return false;
			}
			return true;
		}
		return false;
	}

	public boolean equals(SecuredDecentralizedID sid) {
		if (sid == null)
			return false;
		if (sid.idLongs == null)
			return false;
		if (sid.idLongs.length != idLongs.length)
			return false;
		for (int i = 0; i < idLongs.length; i++) {
			if (idLongs[i] != sid.idLongs[i])
				return false;
		}
		return true;
	}

	@Override
	public WrappedSecretData encode() {
		int sizeLong = ObjectSizer.sizeOf(idLongs[0]);
		byte[] res = new byte[idLongs.length * sizeLong + 1];
		res[0] = getType();

		for (int i = 0; i < idLongs.length; i++) {
			Bits.putLong(res, i * sizeLong + 1, idLongs[i]);
		}
		return new WrappedSecretData(res);
	}

	@Override
	byte getType() {
		return AbstractDecentralizedID.SECURED_DECENTRALIZED_ID_TYPE;
	}

	@Override
	public int hashCode() {
		return hashCode;
	}

	private void readObject(java.io.ObjectInputStream in) throws IOException, ClassNotFoundException {
		try {
			in.defaultReadObject();
			hashCode = computeHashCode(idLongs);
		}
		catch(ClassNotFoundException | IOException e)
		{
			throw e;
		} catch (Exception e) {
			throw new IOException(e);
		}
	}

	@Override
	public String toString() {
		StringBuilder res = new StringBuilder(ToStringHead + "[");
		boolean first = true;
		for (long idLong : idLongs) {
			if (first)
				first = false;
			else
				res.append(";");
			res.append(idLong);
		}
		res.append("]");
		return res.toString();
	}

}

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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.math.BigInteger;

import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.agreement.jpake.JPAKEParticipant;
import org.bouncycastle.crypto.agreement.jpake.JPAKEPrimeOrderGroups;
import org.bouncycastle.crypto.agreement.jpake.JPAKERound1Payload;
import org.bouncycastle.crypto.agreement.jpake.JPAKERound2Payload;
import org.bouncycastle.crypto.agreement.jpake.JPAKERound3Payload;
import org.bouncycastle.crypto.digests.SHA512Digest;

import gnu.vm.jgnu.security.NoSuchAlgorithmException;
import gnu.vm.jgnu.security.NoSuchProviderException;
import gnu.vm.jgnu.security.spec.InvalidKeySpecException;

/**
 * 
 * @author Jason Mahdjoub
 * @version 1.1
 * @since Utils 2.9.0
 */
public class P2PJPAKESecretMessageExchanger {
	private final JPAKEParticipant jpake;
	private BigInteger keyMaterial;

	public P2PJPAKESecretMessageExchanger(Serializable participantID, char[] message)
			throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
		this(participantID, message, null, -1, -1);
	}

	public P2PJPAKESecretMessageExchanger(Serializable participantID, byte[] message, boolean messageIsKey)
			throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
		this(participantID, message, 0, message.length, null, -1, -1, messageIsKey);
	}

	public P2PJPAKESecretMessageExchanger(Serializable participantID, char[] message, byte salt[], int offset_salt,
			int len_salt) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
		if (message == null)
			throw new NullPointerException("message");
		if (salt != null && salt.length - offset_salt < len_salt)
			throw new IllegalArgumentException("salt");

		byte[] m = hashMessage(MessageDigestType.BOUNCY_CASTLE_SHA_256.getMessageDigestInstance(), message, salt,
				offset_salt, len_salt, PasswordHashType.BCRYPT, 10000);
		jpake = new JPAKEParticipant(participantID, m, JPAKEPrimeOrderGroups.NIST_3072, new SHA512Digest(),
				SecureRandomType.DEFAULT.getInstance());
		this.keyMaterial = null;
	}

	public P2PJPAKESecretMessageExchanger(Serializable participantID, byte[] message, int offset, int len, byte salt[],
			int offset_salt, int len_salt, boolean messageIsKey)
			throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
		if (message == null)
			throw new NullPointerException("message");
		if (message.length - offset < len)
			throw new IllegalArgumentException("message");
		if (salt != null && salt.length - offset_salt < len_salt)
			throw new IllegalArgumentException("salt");

		byte[] m = hashMessage(MessageDigestType.BOUNCY_CASTLE_SHA_256.getMessageDigestInstance(), message, offset, len,
				salt, offset_salt, len_salt, messageIsKey ? null : PasswordHashType.BCRYPT, 10000);
		jpake = new JPAKEParticipant(participantID, m, JPAKEPrimeOrderGroups.NIST_3072, new SHA512Digest(),
				SecureRandomType.DEFAULT.getInstance());
		this.keyMaterial = null;
	}

	private static byte[] hashMessage(AbstractMessageDigest messageDigest, byte data[], int off, int len, byte[] salt,
			int offset_salt, int len_salt, PasswordHashType passwordHashType, int hashIterationsNumber)
			throws NoSuchAlgorithmException, InvalidKeySpecException {
		if (passwordHashType != null && salt != null && len_salt > 0) {
			byte s[] = new byte[len_salt];
			System.arraycopy(salt, offset_salt, s, 0, len_salt);
			data = passwordHashType.hash(data, off, len, s, hashIterationsNumber);
			off = 0;
			len = data.length;
		}
		messageDigest.update(data, off, len);
		if (passwordHashType == null && salt != null && len_salt > 0)
			messageDigest.update(salt, offset_salt, len_salt);
		return messageDigest.digest();
	}

	private static byte[] hashMessage(AbstractMessageDigest messageDigest, char password[], byte[] salt,
			int offset_salt, int len_salt, PasswordHashType passwordHashType, int hashIterationsNumber)
			throws NoSuchAlgorithmException, InvalidKeySpecException {
		if (salt != null && len_salt > 0) {
			byte s[] = new byte[len_salt];
			System.arraycopy(salt, offset_salt, s, 0, len_salt);
			byte[] res = passwordHashType.hash(password, s, hashIterationsNumber);
			return hashMessage(messageDigest, res, 0, res.length, null, -1, -1, null, 0);
		} else {
			byte[] res = new byte[password.length * 2];
			for (int i = 0; i < password.length; i++) {
				res[i * 2] = (byte) (password[i] & 0xFF);
				res[i * 2 + 1] = (byte) ((password[i] >> 8) & 0xFF);
			}
			return hashMessage(messageDigest, res, 0, res.length, null, -1, -1, null, 0);
		}

	}

	public byte[] getStep1Message() throws IOException {
		try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
			try (ObjectOutputStream oos = new ObjectOutputStream(baos)) {

				JPAKERound1Payload toSerialize = jpake.createRound1PayloadToSend();
				oos.writeObject(toSerialize);
			}
			return baos.toByteArray();
		}
	}

	public byte[] receiveStep1AndGetStep2Message(byte[] dataReceived)
			throws IOException, CryptoException, ClassNotFoundException {

		try (ByteArrayInputStream bais = new ByteArrayInputStream(dataReceived)) {
			try (ObjectInputStream ois = new ObjectInputStream(bais)) {
				Object o = ois.readObject();
				if (o instanceof JPAKERound1Payload) {
					jpake.validateRound1PayloadReceived((JPAKERound1Payload) o);
				} else
					throw new CryptoException("o is not an instance of JPAKERound1Payload");
			}
		}
		try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
			try (ObjectOutputStream oos = new ObjectOutputStream(baos)) {

				JPAKERound2Payload toSerialize = jpake.createRound2PayloadToSend();
				oos.writeObject(toSerialize);
			}
			return baos.toByteArray();
		}
	}

	public byte[] receiveStep2AndGetStep3Message(byte[] dataReceived)
			throws CryptoException, IOException, ClassNotFoundException {
		try (ByteArrayInputStream bais = new ByteArrayInputStream(dataReceived)) {
			try (ObjectInputStream ois = new ObjectInputStream(bais)) {
				Object o = ois.readObject();
				if (o instanceof JPAKERound2Payload) {
					jpake.validateRound2PayloadReceived((JPAKERound2Payload) o);
				} else
					throw new CryptoException("o is not an instance of JPAKERound2Payload");
			}
		}
		try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
			try (ObjectOutputStream oos = new ObjectOutputStream(baos)) {

				keyMaterial = jpake.calculateKeyingMaterial();
				JPAKERound3Payload toSerialize = jpake.createRound3PayloadToSend(keyMaterial);
				oos.writeObject(toSerialize);
			}
			return baos.toByteArray();
		}
	}

	public void receiveStep3(byte[] dataReceived) throws CryptoException, ClassNotFoundException, IOException {
		try (ByteArrayInputStream bais = new ByteArrayInputStream(dataReceived)) {
			try (ObjectInputStream ois = new ObjectInputStream(bais)) {
				Object o = ois.readObject();
				if (o instanceof JPAKERound3Payload) {
					jpake.validateRound3PayloadReceived((JPAKERound3Payload) o, keyMaterial);
				} else
					throw new CryptoException("o is not an instance of JPAKERound3Payload");
			}
		}

	}

	public boolean isPassworkOrKeyValid() {
		return jpake.getState() == JPAKEParticipant.STATE_ROUND_3_VALIDATED;
	}

}

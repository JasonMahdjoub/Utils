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

import org.apache.commons.codec.binary.Base64;
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
 * @version 2.0
 * @since Utils 2.9.0
 */
public class P2PJPAKESecretMessageExchanger extends Agreement {
	private final JPAKEParticipant jpake;
	private BigInteger keyMaterial;

	public P2PJPAKESecretMessageExchanger(AbstractSecureRandom secureRandom, Serializable participantID, char[] message)
			throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IOException {
		this(secureRandom, participantID, message, null, -1, -1);
	}

	public P2PJPAKESecretMessageExchanger(AbstractSecureRandom secureRandom, Serializable participantID, byte[] message, boolean messageIsKey)
			throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IOException {
		this(secureRandom, participantID, message, 0, message.length, null, -1, -1, messageIsKey);
	}

	private char[] getHashedPassword(char[] message, byte salt[], int offset_salt, int len_salt) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException
	{
		byte[] m = hashMessage(MessageDigestType.BC_FIPS_SHA3_256.getMessageDigestInstance(), message, salt,
				offset_salt, len_salt, PasswordHashType.BCRYPT, 15);
		return convertToChar(m);
	}
	private char[] getHashedPassword(byte[] message, int offset, int len, byte salt[], int offset_salt, int len_salt, boolean messageIsKey) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException
	{
		byte[] m = hashMessage(MessageDigestType.BC_FIPS_SHA3_256.getMessageDigestInstance(), message, offset, len,
				salt, offset_salt, len_salt, messageIsKey ? null : PasswordHashType.BCRYPT, messageIsKey?10:15);
		return convertToChar(m);
	}
	
	private char[] convertToChar(byte[] m)
	{
		char[] res=new char[m.length];
		for (int i=0;i<m.length;i++)
			res[i]=(char)m[i];
		return res;
	}
	
	private String getParticipanIDString(Serializable participantID) throws IOException
	{
		try(ByteArrayOutputStream bais=new ByteArrayOutputStream();ObjectOutputStream oos=new ObjectOutputStream(bais))
		{
			oos.writeObject(participantID);
			return Base64.encodeBase64URLSafeString(bais.toByteArray());
		}
	}
	
	public P2PJPAKESecretMessageExchanger(AbstractSecureRandom secureRandom, Serializable participantID, char[] message, byte salt[], int offset_salt,
			int len_salt) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IOException {
		super(3, 3);
		if (message == null)
			throw new NullPointerException("message");
		if (salt != null && salt.length - offset_salt < len_salt)
			throw new IllegalArgumentException("salt");

		
		jpake = new JPAKEParticipant(getParticipanIDString(participantID), getHashedPassword(message, salt, offset_salt, len_salt), JPAKEPrimeOrderGroups.NIST_3072, new SHA512Digest(),
				secureRandom);
		this.keyMaterial = null;
	}

	public P2PJPAKESecretMessageExchanger(AbstractSecureRandom secureRandom, Serializable participantID, byte[] message, int offset, int len, byte salt[],
			int offset_salt, int len_salt, boolean messageIsKey)
			throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IOException {
		super(3, 3);
		if (message == null)
			throw new NullPointerException("message");
		if (message.length - offset < len)
			throw new IllegalArgumentException("message");
		if (salt != null && salt.length - offset_salt < len_salt)
			throw new IllegalArgumentException("salt");

		jpake = new JPAKEParticipant(getParticipanIDString(participantID), getHashedPassword(message, offset, len, salt, offset_salt, len_salt, messageIsKey), JPAKEPrimeOrderGroups.NIST_3072, new SHA512Digest(),
				secureRandom);
		this.keyMaterial = null;
	}

	private static byte[] hashMessage(AbstractMessageDigest messageDigest, byte data[], int off, int len, byte[] salt,
			int offset_salt, int len_salt, PasswordHashType passwordHashType, int cost)
			throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
		if (passwordHashType != null && salt != null && len_salt > 0) {
			byte s[] = new byte[len_salt];
			System.arraycopy(salt, offset_salt, s, 0, len_salt);
			data = passwordHashType.hash(data, off, len, s, cost, passwordHashType.getDefaultHashLengthBytes());
			off = 0;
			len = data.length;
		}
		messageDigest.update(data, off, len);
		if (passwordHashType == null && salt != null && len_salt > 0)
			messageDigest.update(salt, offset_salt, len_salt);
		return messageDigest.digest();
	}

	private static byte[] hashMessage(AbstractMessageDigest messageDigest, char password[], byte[] salt,
			int offset_salt, int len_salt, PasswordHashType passwordHashType, int cost)
			throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
		if (salt != null && len_salt > 0) {
			byte s[] = new byte[len_salt];
			System.arraycopy(salt, offset_salt, s, 0, len_salt);
			byte[] res = passwordHashType.hash(password, s, cost, passwordHashType.getDefaultHashLengthBytes());
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

	@Override
	protected boolean isAgreementProcessValidImpl() {
		return jpake.getState() == JPAKEParticipant.STATE_ROUND_3_VALIDATED;
	}

	@Override
	protected byte[] getDataToSend(int stepNumber) throws Exception {
		switch(stepNumber)
		{
		case 0:
			try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
				try (ObjectOutputStream oos = new ObjectOutputStream(baos)) {

					JPAKERound1Payload toSerialize = jpake.createRound1PayloadToSend();
					oos.writeObject(toSerialize.getGx1());
					oos.writeObject(toSerialize.getGx2());
					BigInteger[] b=toSerialize.getKnowledgeProofForX1();
					if (b==null)
						oos.writeInt(0);
					else
						oos.writeInt(b.length);
					for (BigInteger bi : b)
						oos.writeObject(bi);
					b=toSerialize.getKnowledgeProofForX2();
					if (b==null)
						oos.writeInt(0);
					else
						oos.writeInt(b.length);
					for (BigInteger bi : b)
						oos.writeObject(bi);
					
					oos.writeObject(toSerialize.getParticipantId());
				}
				return baos.toByteArray();
			}
			
		case 1:
			try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
				try (ObjectOutputStream oos = new ObjectOutputStream(baos)) {

					JPAKERound2Payload toSerialize = jpake.createRound2PayloadToSend();
					oos.writeObject(toSerialize.getA());
					BigInteger[] b=toSerialize.getKnowledgeProofForX2s();
					if (b==null)
						oos.writeInt(0);
					else
						oos.writeInt(b.length);
					for (BigInteger bi : b)
						oos.writeObject(bi);
					oos.writeObject(toSerialize.getParticipantId());
				}
				return baos.toByteArray();
			}
			
		case 2:
			try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
				try (ObjectOutputStream oos = new ObjectOutputStream(baos)) {

					keyMaterial = jpake.calculateKeyingMaterial();
					JPAKERound3Payload toSerialize = jpake.createRound3PayloadToSend(keyMaterial);
					
					oos.writeObject(toSerialize.getMacTag());
					oos.writeObject(toSerialize.getParticipantId());
				}
				return baos.toByteArray();
			}
			
			default:
				throw new IllegalAccessError();

		}
	}

	@Override
	protected void receiveData(int stepNumber, byte[] dataReceived) throws Exception {
		switch(stepNumber)
		{
		case 0:
			try (ByteArrayInputStream bais = new ByteArrayInputStream(dataReceived)) {
				try (ObjectInputStream ois = new ObjectInputStream(bais)) {
					JPAKERound1Payload r1=null;
					try
					{
						BigInteger gx1 = (BigInteger)ois.readObject();
						BigInteger gx2 = (BigInteger)ois.readObject();
						int size=ois.readInt();
						BigInteger knowledgeProofForX1[]=null;
						if (size>0)
						{
							if (size>100)
								throw new CryptoException("illegal argument exception");
							knowledgeProofForX1=new BigInteger[size];
							for (int i=0;i<size;i++)
								knowledgeProofForX1[i]=(BigInteger)ois.readObject();
						}
						size=ois.readInt();
						BigInteger knowledgeProofForX2[]=null;
						if (size>0)
						{
							if (size>100)
								throw new CryptoException("illegal argument exception");
							knowledgeProofForX2=new BigInteger[size];
							for (int i=0;i<size;i++)
								knowledgeProofForX2[i]=(BigInteger)ois.readObject();
						}
						String pid=(String)ois.readObject();
						r1=new JPAKERound1Payload(pid, gx1, gx2, knowledgeProofForX1, knowledgeProofForX2);
					}
					catch(Exception e)
					{
						throw new CryptoException("data received is not a valid instance of JPAKERound1Payload", e);
					}
					jpake.validateRound1PayloadReceived(r1);
				}
			}
			break;
		case 1:
			try (ByteArrayInputStream bais = new ByteArrayInputStream(dataReceived)) {
				try (ObjectInputStream ois = new ObjectInputStream(bais)) {
					JPAKERound2Payload r2=null;
					try
					{
						BigInteger A = (BigInteger)ois.readObject();
						
						int size=ois.readInt();
						BigInteger knowledgeProofForX2s[]=null;
						if (size>0)
						{
							if (size>100)
								throw new CryptoException("illegal argument exception");
							knowledgeProofForX2s=new BigInteger[size];
							for (int i=0;i<size;i++)
								knowledgeProofForX2s[i]=(BigInteger)ois.readObject();
						}
						String pid=(String)ois.readObject();
						r2=new JPAKERound2Payload(pid, A, knowledgeProofForX2s);
					}
					catch(Exception e)
					{
						throw new CryptoException("data received is not a valid instance of JPAKERound2Payload", e);
					}
					jpake.validateRound2PayloadReceived(r2);
				}
			}
			break;
		case 2:
			try (ByteArrayInputStream bais = new ByteArrayInputStream(dataReceived)) {
				try (ObjectInputStream ois = new ObjectInputStream(bais)) {
					JPAKERound3Payload r3=null;
					try
					{
						BigInteger magTag = (BigInteger)ois.readObject();
						String pid=(String)ois.readObject();
						r3=new JPAKERound3Payload(pid, magTag);
					}
					catch(Exception e)
					{
						throw new CryptoException("data received is not a valid instance of JPAKERound2Payload", e);
					}
					
					jpake.validateRound3PayloadReceived(r3, keyMaterial);
				}
			}
			break;
		default:
			throw new IllegalAccessError();
			
			
		}
	}

}

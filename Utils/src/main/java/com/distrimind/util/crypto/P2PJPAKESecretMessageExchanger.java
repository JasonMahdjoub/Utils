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

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.agreement.jpake.*;
import org.bouncycastle.crypto.digests.SHA512Digest;

import java.io.*;
import java.lang.reflect.Field;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

/**
 * 
 * @author Jason Mahdjoub
 * @version 4.0
 * @since Utils 2.9.0
 */
public class P2PJPAKESecretMessageExchanger extends P2PLoginAgreement {
	private JPAKEParticipant jpake;
	private BigInteger keyMaterial;
	private boolean valid=true;

	/*P2PJPAKESecretMessageExchanger(AbstractSecureRandom secureRandom, Serializable participantID, char[] message)
			throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IOException {
		this(secureRandom, participantID, message, null, -1, -1);
	}

	P2PJPAKESecretMessageExchanger(AbstractSecureRandom secureRandom, Serializable participantID, byte[] message, boolean messageIsKey)
			throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IOException {
		this(secureRandom, participantID, message, 0, message.length, null, -1, -1, messageIsKey);
	}*/

	private char[] getHashedPassword(char[] message, byte[] salt, int offset_salt, int len_salt) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException
	{
		byte[] m = hashMessage(MessageDigestType.BC_FIPS_SHA3_256.getMessageDigestInstance(), message, salt,
				offset_salt, len_salt, PasswordHashType.BC_BCRYPT, (byte)15);
		return convertToChar(m);
	}
	private char[] getHashedPassword(byte[] message, int offset, int len, byte[] salt, int offset_salt, int len_salt, boolean messageIsKey) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException
	{
		byte[] m = hashMessage(MessageDigestType.BC_FIPS_SHA3_256.getMessageDigestInstance(), message, offset, len,
				salt, offset_salt, len_salt, messageIsKey ? null : PasswordHashType.BC_FIPS_PBKFD2WithHMacSHA2_512, messageIsKey?(byte)6:(byte)15);
		char[] res=convertToChar(m);
		Arrays.fill(m, (byte)0);
		return res;
	}
	
	private char[] convertToChar(byte[] m)
	{
		char[] res=new char[m.length];
		for (int i=0;i<m.length;i++)
			res[i]=(char)m[i];
		return res;
	}
	
	private String getParticipanIDString(byte[] participantID)
	{
		return Base64.encodeBase64URLSafeString(participantID);
	}
	
	P2PJPAKESecretMessageExchanger(AbstractSecureRandom secureRandom, byte[] participantID, char[] message, byte[] salt, int offset_salt,
								   int len_salt) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
		super(3, 3);
		if (message == null)
			throw new NullPointerException("message");
		if (salt != null && salt.length - offset_salt < len_salt)
			throw new IllegalArgumentException("salt");

		
		jpake = new JPAKEParticipant(getParticipanIDString(participantID), getHashedPassword(message, salt, offset_salt, len_salt), JPAKEPrimeOrderGroups.NIST_3072, new SHA512Digest(),
				secureRandom);
		this.keyMaterial = null;
	}

	P2PJPAKESecretMessageExchanger(AbstractSecureRandom secureRandom, byte[] participantID, byte[] message, int offset, int len, byte[] salt,
								   int offset_salt, int len_salt, boolean messageIsKey)
			throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
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

	private static byte[] hashMessage(AbstractMessageDigest messageDigest, byte[] data, int off, int len, byte[] salt,
									  int offset_salt, int len_salt, PasswordHashType passwordHashType, byte cost)
			throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
		if (passwordHashType != null && salt != null && len_salt > 0) {
			byte[] s = new byte[len_salt];
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

	@SuppressWarnings("SameParameterValue")
	private static byte[] hashMessage(AbstractMessageDigest messageDigest, char[] password, byte[] salt,
									  int offset_salt, int len_salt, PasswordHashType passwordHashType, byte cost)
			throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
		if (salt != null && len_salt > 0) {
			byte[] s = new byte[len_salt];
			System.arraycopy(salt, offset_salt, s, 0, len_salt);
			byte[] res = passwordHashType.hash(password, s, cost, passwordHashType.getDefaultHashLengthBytes());
			return hashMessage(messageDigest, res, 0, res.length, null, -1, -1, null, (byte)0);
		} else {
			byte[] res = new byte[password.length * 2];
			for (int i = 0; i < password.length; i++) {
				res[i * 2] = (byte) (password[i] & 0xFF);
				res[i * 2 + 1] = (byte) ((password[i] >> 8) & 0xFF);
			}
			return hashMessage(messageDigest, res, 0, res.length, null, -1, -1, null, (byte)0);
		}

	}

	@Override
	protected boolean isAgreementProcessValidImpl() {
		if (this.getActualStepForReceptionIndex()==this.getStepsNumberForReception() && this.getActualStepForSendIndex()==this.getStepsNumberForSend() && jpake.getState() != JPAKEParticipant.STATE_ROUND_3_VALIDATED)
			return false;
		return valid;
	}

	@Override
	protected byte[] getDataToSend(int stepNumber) throws Exception {
		valid=false;
		switch(stepNumber)
		{
		case 0:
			try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
				try (DataOutputStream oos = new DataOutputStream(baos)) {

					JPAKERound1Payload toSerialize = jpake.createRound1PayloadToSend();
					byte[] tab=toSerialize.getGx1().toByteArray();
					if (tab.length>Short.MAX_VALUE)
						throw new IOException();
					oos.writeShort(tab.length);
					oos.write(tab);
					tab=toSerialize.getGx2().toByteArray();
					if (tab.length>Short.MAX_VALUE)
						throw new IOException();
					oos.writeShort(tab.length);
					oos.write(tab);

					BigInteger[] b=toSerialize.getKnowledgeProofForX1();
					if (b==null)
						oos.writeInt(0);
					else
						oos.writeInt(b.length);
					if (b==null)
						throw new IOException();

					for (BigInteger bi : b) {
						tab=bi.toByteArray();
						if (tab.length>Short.MAX_VALUE)
							throw new IOException();
						oos.writeShort(tab.length);
						oos.write(tab);
					}
					b=toSerialize.getKnowledgeProofForX2();
					if (b==null)
						oos.writeInt(0);
					else
						oos.writeInt(b.length);
					if (b==null)
						throw new IOException();

					for (BigInteger bi : b) {
						tab=bi.toByteArray();
						if (tab.length>Short.MAX_VALUE)
							throw new IOException();
						oos.writeShort(tab.length);
						oos.write(tab);

					}
					tab=toSerialize.getParticipantId().getBytes(Charset.forName("utf-8"));
					if (tab.length>Short.MAX_VALUE)
						throw new IOException();
					oos.writeShort(tab.length);
					oos.write(tab);
				}
				valid=true;
				return baos.toByteArray();
			}
			
		case 1:
			try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
				try (DataOutputStream oos = new DataOutputStream(baos)) {

					JPAKERound2Payload toSerialize = jpake.createRound2PayloadToSend();
					byte[] tab=toSerialize.getA().toByteArray();
					if (tab.length>Short.MAX_VALUE)
						throw new IOException();
					oos.writeShort(tab.length);
					oos.write(tab);

					BigInteger[] b=toSerialize.getKnowledgeProofForX2s();
					if (b==null)
						oos.writeInt(0);
					else
						oos.writeInt(b.length);
					if (b==null)
						throw new IOException();

					for (BigInteger bi : b) {
						tab=bi.toByteArray();
						if (tab.length>Short.MAX_VALUE)
							throw new IOException();
						oos.writeShort(tab.length);
						oos.write(tab);
					}
					tab=toSerialize.getParticipantId().getBytes(Charset.forName("utf-8"));
					if (tab.length>Short.MAX_VALUE)
						throw new IOException();
					oos.writeShort(tab.length);
					oos.write(tab);
				}
				valid=true;
				return baos.toByteArray();
			}
			
		case 2:
			try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
				try (DataOutputStream oos = new DataOutputStream(baos)) {

					keyMaterial = jpake.calculateKeyingMaterial();
					JPAKERound3Payload toSerialize = jpake.createRound3PayloadToSend(keyMaterial);
					byte[] tab=toSerialize.getMacTag().toByteArray();
					if (tab.length>Short.MAX_VALUE)
						throw new IOException();
					oos.writeShort(tab.length);
					oos.write(tab);

					tab=toSerialize.getParticipantId().getBytes(Charset.forName("utf-8"));
					if (tab.length>Short.MAX_VALUE)
						throw new IOException();
					oos.writeShort(tab.length);
					oos.write(tab);
				}
				valid=true;
				return baos.toByteArray();
			}
			
			default:
				throw new IllegalAccessError();

		}
	}

	@Override
	protected void receiveData(int stepNumber, byte[] dataReceived) throws CryptoException {
		valid=false;
		switch(stepNumber)
		{
		case 0:
			try (ByteArrayInputStream bais = new ByteArrayInputStream(dataReceived)) {
				try (DataInputStream ois = new DataInputStream(bais)) {
					JPAKERound1Payload r1;
					try
					{
						short s=ois.readShort();
						if (s<=0)
							throw new IOException();
						byte[] tab=new byte[s];
						ois.readFully(tab);
						BigInteger gx1 = new BigInteger(tab);

						s=ois.readShort();
						if (s<=0)
							throw new IOException();
						tab=new byte[s];
						ois.readFully(tab);
						BigInteger gx2 = new BigInteger(tab);

						int size=ois.readInt();
						BigInteger[] knowledgeProofForX1 = null;
						if (size>0)
						{
							if (size>100)
								throw new CryptoException("illegal argument exception");
							knowledgeProofForX1=new BigInteger[size];
							for (int i=0;i<size;i++) {
								s=ois.readShort();
								if (s<=0)
									throw new IOException();
								tab=new byte[s];
								ois.readFully(tab);
								knowledgeProofForX1[i] = new BigInteger(tab);
							}
						}
						size=ois.readInt();
						BigInteger[] knowledgeProofForX2 = null;
						if (size>0)
						{
							if (size>100)
								throw new CryptoException("illegal argument exception");
							knowledgeProofForX2=new BigInteger[size];
							for (int i=0;i<size;i++) {
								s=ois.readShort();
								if (s<=0)
									throw new IOException();
								tab=new byte[s];
								ois.readFully(tab);
								knowledgeProofForX2[i] = new BigInteger(tab);
							}
						}
						s=ois.readShort();
						if (s<=0)
							throw new IOException();
						tab=new byte[s];
						ois.readFully(tab);
						String pid=new String(tab, Charset.forName("utf-8"));
						if (knowledgeProofForX1==null)
							throw new IOException();
						if (knowledgeProofForX2==null)
							throw new IOException();
						r1=new JPAKERound1Payload(pid, gx1, gx2, knowledgeProofForX1, knowledgeProofForX2);
					}
					catch(Exception e)
					{
						valid=false;
						throw new CryptoException("data received is not a valid instance of JPAKERound1Payload", e);
					}
					jpake.validateRound1PayloadReceived(r1);
				}
			}
			catch (Exception e)
			{
				valid = false;
				if (e instanceof CryptoException)
					throw (CryptoException)e;
				else
					throw new CryptoException("", e);
			}
			break;
		case 1:
			try (ByteArrayInputStream bais = new ByteArrayInputStream(dataReceived)) {
				try (DataInputStream ois = new DataInputStream(bais)) {
					JPAKERound2Payload r2;
					try
					{
						short s=ois.readShort();
						if (s<=0)
							throw new IOException();
						byte[] tab=new byte[s];
						ois.readFully(tab);
						BigInteger A = new BigInteger(tab);


						int size=ois.readInt();
						BigInteger[] knowledgeProofForX2s = null;
						if (size>0)
						{
							if (size>100)
								throw new CryptoException("illegal argument exception");
							knowledgeProofForX2s=new BigInteger[size];
							for (int i=0;i<size;i++) {
								s=ois.readShort();
								if (s<=0)
									throw new IOException();
								tab=new byte[s];
								ois.readFully(tab);
								knowledgeProofForX2s[i] = new BigInteger(tab);
							}
						}
						s=ois.readShort();
						if (s<=0)
							throw new IOException();
						tab=new byte[s];
						ois.readFully(tab);
						String pid=new String(tab, Charset.forName("utf-8"));

						if (knowledgeProofForX2s==null)
							throw new IOException();

						r2=new JPAKERound2Payload(pid, A, knowledgeProofForX2s);
					}
					catch(Exception e)
					{
						valid=false;
						throw new CryptoException("data received is not a valid instance of JPAKERound2Payload", e);
					}
					jpake.validateRound2PayloadReceived(r2);
				}
			}
			catch (Exception e)
			{
				valid = false;
				if (e instanceof CryptoException)
					throw (CryptoException)e;
				else
					throw new CryptoException("", e);
			}
			break;
		case 2:
			try (ByteArrayInputStream bais = new ByteArrayInputStream(dataReceived)) {
				try (DataInputStream ois = new DataInputStream(bais)) {
					JPAKERound3Payload r3;
					try
					{
						short s=ois.readShort();
						if (s<=0)
							throw new IOException();
						byte[] tab=new byte[s];
						ois.readFully(tab);
						BigInteger magTag = new BigInteger(tab);


						s=ois.readShort();
						if (s<=0)
							throw new IOException();
						tab=new byte[s];
						ois.readFully(tab);
						String pid=new String(tab, Charset.forName("utf-8"));

						r3=new JPAKERound3Payload(pid, magTag);
					}
					catch(Exception e)
					{
						valid=false;
						throw new CryptoException("data received is not a valid instance of JPAKERound2Payload", e);
					}
					
					jpake.validateRound3PayloadReceived(r3, keyMaterial);
				}
			}
			catch (Exception e)
			{
				valid = false;
				if (e instanceof CryptoException)
					throw (CryptoException)e;
				else
					throw new CryptoException("", e);
			}
			break;
		default:
			throw new IllegalAccessError();
			
			
		}
		valid=true;
	}
	
	@Override
	public void zeroize()
	{
		if (jpake!=null)
		{
			try {
				char[] chars = (char[]) jpakeFieldPassword.get(jpake);
				if (chars!=null)
					Arrays.fill(chars, (char)0);
				
				
			} catch (IllegalArgumentException | IllegalAccessException e) {
				e.printStackTrace();
			}
			
			jpake=null;
		}
		keyMaterial=null;
	}
	

	private static final Field jpakeFieldPassword;
	static
	{
		jpakeFieldPassword=getField(JPAKEParticipant.class, "password");
	}
	@SuppressWarnings("SameParameterValue")
	private static Field getField(final Class<?> c, final String fieldName) {
		try {
			
			return AccessController.doPrivileged(new PrivilegedExceptionAction<Field>() {

                @Override
                public Field run() throws Exception {
                    Field m = c.getDeclaredField(fieldName);
                    m.setAccessible(true);
                    return m;
                }
            });

				
		} catch (SecurityException | PrivilegedActionException  e) {
			e.printStackTrace();
			System.exit(-1);
			return null;
		}
	}
}

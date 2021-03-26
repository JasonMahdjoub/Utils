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

import java.io.IOException;
import java.io.ObjectInputStream;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Enumeration;

import com.distrimind.util.crypto.*;
import com.distrimind.util.data_buffers.WrappedData;
import com.distrimind.util.data_buffers.WrappedSecretData;
import com.distrimind.util.sizeof.ObjectSizer;

/**
 * This class represents a unique identifier. Uniqueness is guaranteed over the
 * network.
 * 
 * @author Jason Mahdjoub
 * @version 2.3
 * @since Utils 1.0
 * 
 */
public abstract class AbstractDecentralizedIDGenerator extends AbstractDecentralizedID {
	/**
	* 
	*/
	private static final long serialVersionUID = 478117044055632008L;
	public static final int MAX_DECENTRALIZED_ID_SIZE_IN_BYTES=17;

	private final static transient long LOCAL_MAC;
	private final static transient byte []LOCAL_MAC_BYTES;
	//private final static transient long SHORT_LOCAL_MAC;
	private final static transient byte[] SHORT_LOCAL_MAC_BYTES;
	protected final static transient AbstractSecureRandom RANDOM;
	private final static transient AbstractMessageDigest MESSAGE_DIGEST;
	
	
	static {
		long result = 0;
		//short resultShort=0;
		byte[] shortLocalMacBytes = new byte[6];
		AbstractSecureRandom random=null;
		AbstractMessageDigest messageDigest=null;
		byte[] digestion48 = null;
		try {
			@SuppressWarnings("SpellCheckingInspection")
			byte[] nonce=("Que(3) j(1)'aime(4) à(1) faire(5) apprendre ce nombre utile aux sages !\n" +
					"Immortel Archimède, artiste ingénieur,\n" +
					"Qui de ton jugement peut priser la valeur ?\n" +
					"Pour moi, ton problème eut de pareils avantages.\n" +
					"Jadis, mystérieux, un problème bloquait\n" +
					"Tout l'admirable procédé, l'œuvre grandiose\n" +
					"Que Pythagore découvrit aux anciens Grecs.\n" +
					"Ô quadrature ! Vieux tourment du philosophe\n" +
					"Insoluble rondeur, trop longtemps vous avez\n" +
					"Défié Pythagore et ses imitateurs.\n" +
					"Comment intégrer l'espace plan circulaire ?\n" +
					"Former un triangle auquel il équivaudra ?\n" +
					"Nouvelle invention : Archimède inscrira\n" +
					"Dedans un hexagone ; appréciera son aire\n" +
					"Fonction du rayon. Pas trop ne s'y tiendra :\n" +
					"Dédoublera chaque élément antérieur ;\n" +
					"Toujours de l'orbe calculée approchera ;\n" +
					"Définira limite ; enfin, l'arc, le limiteur\n" +
					"De cet inquiétant cercle, ennemi trop rebelle\n" +
					"Professeur, enseignez son problème avec zèle. "+result).getBytes();
			random=SecureRandomType.BC_FIPS_APPROVED.getInstance(nonce);
			messageDigest=MessageDigestType.BC_FIPS_SHA3_256.getMessageDigestInstance();
			byte[] hardwareAddress = null;
			byte[] hardwareAddress2 = null;

			try {
				final Enumeration<NetworkInterface> e = NetworkInterface.getNetworkInterfaces();

				while (e.hasMoreElements()) {
					final NetworkInterface ni = e.nextElement();


					if (!ni.isLoopback()) {

						byte[] t = ni.getHardwareAddress();
						if (t == null)
							continue;
						if (t[0]==2)
						{
							boolean all0=true;
							for (int i=1;i<t.length;i++) {
								if (t[i]!=0) {
									all0 = false;
									break;
								}
							}
							if (all0)
								t=null;
						}
						else if (t[t.length-1]==0)
						{
							boolean all0=true;
							for (int i=t.length-2;i>=0;i--) {
								if (t[i]!=0) {
									all0 = false;
									break;
								}
							}
							if (all0)
								t=null;
						}

						long val = getHardwareAddress(t);
						if (val != 0 && val != 224)// is the current network interface is not a virtual interface
						{
							if (ni.isPointToPoint())
							{
								hardwareAddress2=t;
							}
							else {
								hardwareAddress = t;
								break;
							}
						}
					}

				}
			}
			catch (NullPointerException | SocketException e)
			{
				e.printStackTrace();
			}

			if (hardwareAddress==null)
			{
				if (hardwareAddress2!=null)
					hardwareAddress=hardwareAddress2;
				/*else {
					hardwareAddress = new byte[48];
					random.nextBytes(hardwareAddress);
				}*/
			}
			if (hardwareAddress!=null) {
				digestion48=new byte[6];
				byte[] digestion256 = messageDigest.digest(hardwareAddress);
				byte[] digestion64 = new byte[8];
				for (int i = 0; i < 8; i++)
					digestion64[i] = (byte) (digestion256[i] ^ digestion256[i + 8] ^ digestion256[i + 16] ^ digestion256[i + 24]);

				for (int i = 0; i < 2; i++)
					digestion48[i] = (byte) (digestion64[i] ^ digestion64[i + 2]);
				System.arraycopy(digestion64, 4, digestion48, 2, 4);
				//byte digestion16[]=new byte[2];
				for (int i = 0; i < 2; i++)
					shortLocalMacBytes[i] = (byte) (digestion64[i] ^ digestion64[i + 2] + digestion64[i + 4] + digestion64[i + 6]);

				result = getHardwareAddress(digestion48);
			}


		} catch (NoSuchAlgorithmException | NoSuchProviderException e1) {
			e1.printStackTrace();
			System.exit(-1);
		}
		LOCAL_MAC = result;
		LOCAL_MAC_BYTES=digestion48;
		//SHORT_LOCAL_MAC=0xFFFFl & resultShort;
		RANDOM=random;
		MESSAGE_DIGEST=messageDigest;
		SHORT_LOCAL_MAC_BYTES=shortLocalMacBytes;
	}

	private static long getHardwareAddress(byte[] hardwareAddress) {
		long result = 0;
		if (hardwareAddress != null) {
			for (final byte value : hardwareAddress) {
				result <<= 8;
				result |= value & 255;
			}
		}
		return result;
	}

	protected final long timestamp;
	protected final long worker_id_and_sequence;
	private transient int hashCode;
	public AbstractDecentralizedIDGenerator() {
		this(true, false);
	}
	public AbstractDecentralizedIDGenerator(boolean useShortMacAddressAndRandomNumber, boolean hashAllIdentifier) {
		
		if (hashAllIdentifier)
		{
			long timestamp = System.currentTimeMillis();
			byte[] digestion256;
			synchronized(RANDOM)
			{
				MESSAGE_DIGEST.reset();
				if (LOCAL_MAC==0)
				{
					byte[] r = new byte[6];
					RANDOM.nextBytes(r);
					MESSAGE_DIGEST.update(r);
				}
				else {
					MESSAGE_DIGEST.update(LOCAL_MAC_BYTES);
					byte[] r = new byte[4];
					RANDOM.nextBytes(r);
					MESSAGE_DIGEST.update(r);
				}
				byte[] ts=new byte[10];
				Bits.putLong(ts, 0, timestamp);
				Bits.putShort(ts, 8, getNewSequence());
				MESSAGE_DIGEST.update(ts);
				digestion256=MESSAGE_DIGEST.digest();
			}
			this.timestamp=Bits.getLong(digestion256, 0);
			worker_id_and_sequence=Bits.getLong(digestion256, 8);
		}
		else
		{
			timestamp = System.currentTimeMillis();

			if (useShortMacAddressAndRandomNumber)
			{
				//long r=0;
				byte[] digestion256;
				synchronized(RANDOM)
				{
					MESSAGE_DIGEST.reset();
					if (LOCAL_MAC==0)
					{
						byte[] r = new byte[6];
						RANDOM.nextBytes(r);
						MESSAGE_DIGEST.update(r);
					}
					else {
						MESSAGE_DIGEST.update(SHORT_LOCAL_MAC_BYTES, 0, 2);
						byte[] r = new byte[4];
						RANDOM.nextBytes(r);
						MESSAGE_DIGEST.update(r, 0, 4);
					}
					digestion256=MESSAGE_DIGEST.digest();
					
					
					
					//r=0xFFFFFFFFFFFFFFFFl & ((long)RANDOM.nextInt());
				}
				digestion256[0]=0;
				digestion256[1]=0;
				
				//worker_id_and_sequence = SHORT_LOCAL_MAC | ((0xFFFFFFFFl & r)<<16) | ((0xFFFFl & getNewSequence()) << 48);
				worker_id_and_sequence = Bits.getLong(digestion256, 0) | ((0xFFFFL & getNewSequence()) << 48);
			}
			else {
				if (LOCAL_MAC==0)
				{
					worker_id_and_sequence = (RANDOM.nextLong() & 0xFFFFFFFFFFFFL) | ((0xFFFFL & getNewSequence()) << 48);
				}
				else {
					worker_id_and_sequence = LOCAL_MAC | ((0xFFFFL & getNewSequence()) << 48);
				}
			}
		}
		hashCode=computeHashCode();
	}
	private int computeHashCode()
	{
		return 31 * ((int)(timestamp ^ (timestamp >>> 32))) + ((int)(worker_id_and_sequence ^ (worker_id_and_sequence >>> 32)));
	}
	private void readObject(ObjectInputStream aInputStream) throws ClassNotFoundException, IOException
	{
		aInputStream.defaultReadObject();
		hashCode=computeHashCode();
	}

	AbstractDecentralizedIDGenerator(long timestamp, long work_id_sequence) {
		this.timestamp = timestamp;
		this.worker_id_and_sequence = work_id_sequence;
		hashCode=computeHashCode();
	}

	public boolean equals(AbstractDecentralizedIDGenerator other) {
		if (other == null)
			return false;
		return timestamp == other.timestamp && worker_id_and_sequence == other.worker_id_and_sequence;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (obj instanceof AbstractDecentralizedIDGenerator)
			return equals((AbstractDecentralizedIDGenerator) obj);
		return false;
	}

	@Override
	public WrappedData encode() {
		long ts = getTimeStamp();
		long wid = getWorkerIDAndSequence();
		int sizeLong = ObjectSizer.sizeOf(ts);
		byte[] res = new byte[sizeLong * 2 + 1];
		res[0] = getType();
		Bits.putLong(res, 1, ts);
		Bits.putLong(res, sizeLong + 1, wid);
		return new WrappedData(res);
	}

	protected abstract short getNewSequence();

	public short getSequenceID() {
		return (short) ((worker_id_and_sequence >>> 48) & 0xFFFFL);
	}

	public long getTimeStamp() {
		return timestamp;
	}

	public long getWorkerID() {
		return worker_id_and_sequence & 0xFFFFFFFFFFFFL;
	}

	public long getWorkerIDAndSequence() {
		return worker_id_and_sequence;
	}

	@Override
	public int hashCode() {
		return hashCode;
	}

}

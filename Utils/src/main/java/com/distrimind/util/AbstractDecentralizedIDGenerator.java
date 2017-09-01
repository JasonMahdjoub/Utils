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

import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.Enumeration;

import com.distrimind.util.crypto.AbstractSecureRandom;
import com.distrimind.util.crypto.FortunaSecureRandom;
import com.distrimind.util.crypto.MessageDigestType;
import com.distrimind.util.sizeof.ObjectSizer;

import gnu.vm.jgnu.security.NoSuchAlgorithmException;
import gnu.vm.jgnu.security.NoSuchProviderException;

/**
 * This class represents a unique identifier. Uniqueness is guaranteed over the
 * network.
 * 
 * @author Jason Mahdjoub
 * @version 2.0
 * @since Utils 1.0
 * 
 */
public abstract class AbstractDecentralizedIDGenerator extends AbstractDecentralizedID {
	/**
	* 
	*/
	private static final long serialVersionUID = 478117044055632008L;

	private final static transient long LOCAL_MAC;
	private final static transient long SHORT_LOCAL_MAC;
	private final static transient AbstractSecureRandom RANDOM;

	static {
		long result = 0;
		long result2 = 0;
		short resultShort=0;
		AbstractSecureRandom random=null;
		try {
			final Enumeration<NetworkInterface> e = NetworkInterface.getNetworkInterfaces();
			if (e != null) {
				while (e.hasMoreElements()) {
					final NetworkInterface ni = e.nextElement();
						
					
					if (!ni.isLoopback()) {
						byte digestion256[]=MessageDigestType.BOUNCY_CASTLE_SHA3_256.getMessageDigestInstance().digest(ni.getHardwareAddress());
						byte digestion64[]=new byte[8];
						for (int i=0;i<8;i++)
							digestion64[i]=(byte)(digestion256[i]^digestion256[i+8]^digestion256[i+16]^digestion256[i+24]);
						byte digestion48[]=new byte[6];
						for (int i=0;i<2;i++)
							digestion48[i]=(byte)(digestion64[i]^digestion64[i+2]);
						for (int i=2;i<6;i++)
							digestion48[i]=digestion64[i+2];
						byte digestion16[]=new byte[2];
						for (int i=0;i<2;i++)
							digestion16[i]=(byte)(digestion64[i]^digestion64[i+2]+digestion64[i+4]+digestion64[i+6]);
						resultShort=Bits.getShort(digestion16, 0);
						
						long val = getHardwareAddress(digestion48);
						if (val != 0 && val != 224)// is the current network
						// interface is not a virtual
						// interface
						{
							if (ni.isPointToPoint()) {
								result2 = val;
							} else {
								result = val;
								break;
							}
						}
					}
				}
			}
			random=new FortunaSecureRandom();
		} catch (SocketException | NoSuchAlgorithmException | NoSuchProviderException e1) {
			e1.printStackTrace();
		}
		if (result == 0)
			result = result2;
		LOCAL_MAC = result;
		SHORT_LOCAL_MAC=0xFFFFl & resultShort;
		RANDOM=random;
	}

	private static long getHardwareAddress(byte hardwareAddress[]) {
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
	public AbstractDecentralizedIDGenerator() {
		this(true);
	}
	public AbstractDecentralizedIDGenerator(boolean useShortMacAddressAndRandomNumber) {
		timestamp = System.currentTimeMillis();
		if (useShortMacAddressAndRandomNumber)
		{
			long r=0;
			synchronized(RANDOM)
			{
				r=0xFFFFFFFFFFFFFFFFl & ((long)RANDOM.nextInt());
			}
			worker_id_and_sequence = SHORT_LOCAL_MAC | ((0xFFFFFFFFl & r)<<16) | ((0xFFFFl & getNewSequence()) << 48);
		}
		else
			worker_id_and_sequence = LOCAL_MAC | ((0xFFFFl & getNewSequence()) << 48);
	}

	AbstractDecentralizedIDGenerator(long timestamp, long work_id_sequence) {
		this.timestamp = timestamp;
		this.worker_id_and_sequence = work_id_sequence;
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
	public byte[] getBytes() {
		long ts = getTimeStamp();
		long wid = getWorkerIDAndSequence();
		int sizeLong = ObjectSizer.sizeOf(ts);
		byte res[] = new byte[sizeLong * 2 + 1];
		res[0] = getType();
		Bits.putLong(res, 1, ts);
		Bits.putLong(res, sizeLong + 1, wid);
		return res;
	}

	protected abstract short getNewSequence();

	public short getSequenceID() {
		return (short) ((worker_id_and_sequence >>> 48) & 0xFFFFl);
	}

	public long getTimeStamp() {
		return timestamp;
	}

	public long getWorkerID() {
		return worker_id_and_sequence & 0xFFFFFFFFFFFFl;
	}

	public long getWorkerIDAndSequence() {
		return worker_id_and_sequence;
	}

	@Override
	public int hashCode() {
		return (int) (timestamp + worker_id_and_sequence);
	}

}

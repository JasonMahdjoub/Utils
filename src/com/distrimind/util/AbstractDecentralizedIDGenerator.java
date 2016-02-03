/*
 * Utils is created and developped by Jason MAHDJOUB (jason.mahdjoub@distri-mind.fr) at 2016.
 * MadKitGroup extension was developped by Jason Mahdjoub. 
 * Individual contributors are indicated by the @authors tag.
 * 
 * This file is part of Utils.
 * 
 * This is free software; you can redistribute it and/or modify it under the
 * terms of the GNU General Public License Lesser as published by the Free
 * Software Foundation; either version 3.0 of the License.
 * 
 * This software is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
 * details.
 * 
 * You should have received a copy of the GNU Lesser General Public License
 * along with this software; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA, or see the FSF
 * site: http://www.fsf.org.
 */
package com.distrimind.util;

import java.io.Serializable;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.Enumeration;


/**
 * This class represents a unique identifier.
 * Uniqueness is guaranteed over the network.
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 1.0
 * 
 */
public abstract class AbstractDecentralizedIDGenerator implements Serializable
{
	/**
     * 
     */
    private static final long serialVersionUID = 478117044055632008L;
    
    private static long getHardwareAddress(byte hardwareAddress[])
    {
	long result=0;
	if (hardwareAddress != null) {
		for (final byte value : hardwareAddress) {
			result <<= 8;
			result |= value & 255;
		}
	}
	return result;
    }
    
	private final static transient long	LOCAL_MAC;
	static {
		long result = 0;
		long result2 = 0;
		try {
			final Enumeration<NetworkInterface> e = NetworkInterface.getNetworkInterfaces();
			if (e != null) {
				while (e.hasMoreElements()) {
					final NetworkInterface ni = e.nextElement();
					
					if (!ni.isLoopback()) {
					    long val=getHardwareAddress(ni.getHardwareAddress());
					    if (val!=0 && val!=224)//is the current network interface is not a virtual interface
					    {
						if (ni.isPointToPoint())
						{
						    result2=val;
						}
						else
						{
						    result=val;
						    break;
						}
					    }
					}
				}
			}
		} catch (SocketException e1) {
			e1.printStackTrace();
		}
		if (result==0)
		    result=result2;
		LOCAL_MAC = result;
	}
	
	protected final long timestamp;
	protected final long worker_id_and_sequence;
	
	public AbstractDecentralizedIDGenerator()
	{
	    timestamp=System.currentTimeMillis();
	    worker_id_and_sequence=LOCAL_MAC & (((long)getNewSequence())<<48);
	}
	
	
	protected abstract short getNewSequence();
	
	@Override public boolean equals(Object obj)
	{
	    if (this==obj)
		return true;
	    if (obj==null)
		return false;
	    if (obj instanceof AbstractDecentralizedIDGenerator)
		return equals((AbstractDecentralizedIDGenerator)obj);
	    return false;
	}
	public boolean equals(AbstractDecentralizedIDGenerator other)
	{
	    if (other == null)
		return false;
	    return timestamp==other.timestamp && worker_id_and_sequence==other.worker_id_and_sequence;
	}
	
	@Override public int hashCode()
	{
	    return (int)(timestamp+worker_id_and_sequence);
	}
	
	@Override public String toString()
	{
	    return "DecentralizedID["+getTimeStamp()+";"+getWorkerID()+";"+getSequenceID()+"]";
	}
	
	public long getTimeStamp()
	{
	    return timestamp;
	}
	
	public long getWorkerID()
	{
	    return worker_id_and_sequence & (1<<48-1);
	}
	public short getSequenceID()
	{
	    return (short)(worker_id_and_sequence>>48 & (1<<16-1));
	}
	
	public long getWorkerIDAndSequence()
	{
	    return worker_id_and_sequence;
	}
	
}

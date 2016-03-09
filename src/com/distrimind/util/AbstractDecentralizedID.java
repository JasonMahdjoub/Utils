/*
 * Utils is created and developped by Jason MAHDJOUB (jason.mahdjoub@distri-mind.fr) at 2016.
 * Utils was developped by Jason Mahdjoub. 
 * Individual contributors are indicated by the @authors tag.
 * 
 * This file is part of Utils.
 * 
 * This is free software; you can redistribute it and/or modify it under the
 * terms of the GNU Lesser General Public License as published by the Free
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

import com.distrimind.util.sizeof.ObjectSizer;

/**
 * This class represents a unique identifier.
 * Uniqueness is guaranteed over the network.
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 1.3
 * 
 */
public abstract class AbstractDecentralizedID implements Serializable
{
    /**
     * 
     */
    private static final long serialVersionUID = 9204239435623960497L;
    
    
    @Override public abstract boolean equals(Object obj);
    @Override public abstract int hashCode();
    @Override public abstract String toString();
    public abstract byte[] getBytes();
    abstract byte getType();
    
    static final byte DECENTRALIZED_ID_GENERATOR_TYPE=0;
    static final byte RENFORCED_DECENTRALIZED_ID_GENERATOR_TYPE=1;
    static final byte SECURED_DECENTRALIZED_ID_TYPE=2;
 
    public static AbstractDecentralizedID instanceOf(byte[] bytes)
    {
	return instanceOf(bytes, 0, bytes.length);
    }
	public static AbstractDecentralizedID instanceOf(byte[] bytes, int off, int len)
	{
	    if (bytes==null)
		throw new NullPointerException("bytes");
	    if (off>=bytes.length)
		throw new IllegalArgumentException();
	    if (off+len>bytes.length)
		throw new IllegalArgumentException();
	    
	    byte type=bytes[off];
	    int sizeLong=ObjectSizer.sizeOf(1l);
	    int sizeByte=ObjectSizer.sizeOf(type);
	    switch(type)
	    {
		case AbstractDecentralizedID.DECENTRALIZED_ID_GENERATOR_TYPE:
		    if (len!=sizeByte+sizeLong*2)
			throw new IllegalArgumentException();
		    return new DecentralizedIDGenerator(Bits.getLong(bytes, off+sizeByte), Bits.getLong(bytes, off+sizeByte+sizeLong));
		case AbstractDecentralizedID.RENFORCED_DECENTRALIZED_ID_GENERATOR_TYPE:
		    if (len!=sizeByte+sizeLong*2)
			throw new IllegalArgumentException();
		    return new RenforcedDecentralizedIDGenerator(Bits.getLong(bytes, off+sizeByte), Bits.getLong(bytes, off+sizeByte+sizeLong));
		case AbstractDecentralizedID.SECURED_DECENTRALIZED_ID_TYPE:
		    if (len!=sizeByte+sizeLong*4)
			throw new IllegalArgumentException();
		    return new SecuredDecentralizedID(Bits.getLong(bytes, off+sizeByte), Bits.getLong(bytes, off+sizeByte+sizeLong), Bits.getLong(bytes, off+sizeByte+sizeLong*2), Bits.getLong(bytes, off+sizeByte+sizeLong*3));
		default:
		    throw new IllegalArgumentException("Unkown type");
	    }
	    
	}
    
}

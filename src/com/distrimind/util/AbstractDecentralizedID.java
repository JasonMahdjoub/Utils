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
		{
		    if ((len-sizeByte)%sizeLong!=0 || (len-sizeByte)/sizeLong<=0)
			throw new IllegalArgumentException();
		    long idLongs[]=new long[(len-sizeByte)/sizeLong];
		    for (int i=0;i<idLongs.length;i++)
			idLongs[i]=Bits.getLong(bytes, off+sizeByte+i*sizeLong);
		    return new SecuredDecentralizedID(idLongs);
		}
		default:
		    throw new IllegalArgumentException("Unkown type");
	    }
	    
	}
    
}

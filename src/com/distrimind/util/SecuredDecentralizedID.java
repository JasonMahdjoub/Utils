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

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * This class represents a unique identifier.
 * Uniqueness is guaranteed over the network.
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 1.3
 * 
 */
public class SecuredDecentralizedID extends AbstractDecentralizedID
{

    /**
     * 
     */
    private static final long serialVersionUID = 4728193961114275589L;
    
    
    private static final MessageDigest message_digest;
    
    static
    {
	MessageDigest m=null;
	try
	{
	    m=MessageDigest.getInstance("SHA-256");
	}
	catch (NoSuchAlgorithmException e)
	{
	    e.printStackTrace();
	    System.exit(-1);
	}
	message_digest=m;
    }
    
    private final long id1, id2, id3, id4;
    public SecuredDecentralizedID(AbstractDecentralizedIDGenerator generator)
    {
	message_digest.update(generator.getBytes());
	byte []id=message_digest.digest();
	id1=Bits.getLong(id, 0);
	id2=Bits.getLong(id, 8);
	id3=Bits.getLong(id, 16);
	id4=Bits.getLong(id, 24);
	message_digest.reset();
    }

    @Override
    public boolean equals(Object _obj)
    {
	if (_obj==null)
	    return false;
	if (_obj==this)
	    return true;
	if (_obj instanceof SecuredDecentralizedID)
	{
	    SecuredDecentralizedID sid=(SecuredDecentralizedID)_obj;
	    return sid.id1==this.id1 && sid.id2==this.id2 && sid.id3==this.id3 && sid.id4==this.id4;
	}
	return false;
    }
    
    public boolean equals(SecuredDecentralizedID sid)
    {
	if (sid==null)
	    return false;
	return sid.id1==this.id1 && sid.id2==this.id2 && sid.id3==this.id3 && sid.id4==this.id4;
    }

    @Override
    public int hashCode()
    {
	return (int)(id1+id2+id3+id4);
    }

    @Override
    public String toString()
    {
	return "SecuredDecentralizedID["+id1+";"+id2+";"+id3+";"+id4+"]";
    }

    @Override
    public byte[] getBytes()
    {
	byte res[]=new byte[32];
	Bits.putLong(res, 0, id1);
	Bits.putLong(res, 8, id2);
	Bits.putLong(res, 16, id3);
	Bits.putLong(res, 24, id4);
	return res;
    }
    
}

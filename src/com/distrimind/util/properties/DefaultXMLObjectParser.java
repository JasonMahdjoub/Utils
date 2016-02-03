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

package com.distrimind.util.properties;

import java.io.File;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URL;
import java.sql.Date;
import java.time.LocalTime;
import java.util.logging.Level;

/**
 * 
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 1.0
 */
public class DefaultXMLObjectParser extends AbstractXMLObjectParser
{

    /**
     * {@inheritDoc}
     */
    @Override
    public Object convertXMLToObject(Class<?> field_type, String nodeValue) throws Exception
    {
	    if (nodeValue==null)
		return null;
	    nodeValue=nodeValue.trim();
	    if (field_type==Boolean.class)
	    {
		return new Boolean(Boolean.parseBoolean(nodeValue));
	    }
	    else if (field_type==Byte.class)
	    {
		return new Byte(Byte.parseByte(nodeValue));
	    }
	    else if (field_type==Short.class)
	    {
		return new Short(Short.parseShort(nodeValue));
	    }
	    else if (field_type==Integer.class)
	    {
		return new Integer(Integer.parseInt(nodeValue));
	    }
	    else if (field_type==Long.class)
	    {
		return new Long(Long.parseLong(nodeValue));
	    }
	    else if (field_type==Float.class)
	    {
		return new Float(Float.parseFloat(nodeValue));
	    }
	    else if (field_type==Double.class)
	    {
		return new Double(Double.parseDouble(nodeValue));		    
	    }
	    else if (field_type==Character.class)
	    {
		return new Character(nodeValue.charAt(0));
	    }
	    else if (field_type==String.class)
	    {
		return nodeValue;
	    }
	    else if (field_type==Class.class)
	    {
		return Class.forName(nodeValue);
	    }
	    else if (field_type==Date.class)
	    {
		return Date.valueOf(nodeValue);
	    }
	    else if (field_type==File.class)
	    {
		return new File(nodeValue);
	    }
	    else if (field_type==URL.class)
	    {
		return new URL(nodeValue);
	    }
	    else if (field_type==URI.class)
	    {
		return new URI(nodeValue);
	    }
	    else if (field_type==LocalTime.class)
	    {
		return LocalTime.parse(nodeValue);
	    }
	    else if (field_type==Level.class)
	    {
		return Level.parse(nodeValue);
	    }
	    else if (field_type==InetAddress.class)
	    {
		return InetAddress.getByName(nodeValue);
	    }
	    else if (field_type==Inet4Address.class)
	    {
		InetAddress res=InetAddress.getByName(nodeValue);
		if (!(res instanceof Inet4Address))
		    return Void.TYPE;
		else
		    return res;
	    }
	    else if (field_type==Inet6Address.class)
	    {
		InetAddress res=InetAddress.getByName(nodeValue);
		if (!(res instanceof Inet6Address))
		    return Void.TYPE;
		else
		    return res;
	    }
	    else if (field_type==InetSocketAddress.class)
	    {
		String split[]=nodeValue.split(":");
		if (split.length!=2)
		    return Void.TYPE;
		return new InetSocketAddress(InetAddress.getByName(split[0]), Integer.parseInt(split[1]));
	    }
	    return Void.TYPE;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String convertObjectToXML(Class<?> field_type, Object object) throws Exception
    {
	    if (field_type==Boolean.class)
	    {
		return object.toString();
	    }
	    else if (field_type==Byte.class)
	    {
		return object.toString();
	    }
	    else if (field_type==Short.class)
	    {
		return object.toString();
	    }
	    else if (field_type==Integer.class)
	    {
		return object.toString();
	    }
	    else if (field_type==Long.class)
	    {
		return object.toString();
	    }
	    else if (field_type==Float.class)
	    {
		return object.toString();
	    }
	    else if (field_type==Double.class)
	    {
		return object.toString();
	    }
	    else if (field_type==Character.class)
	    {
		return object.toString();
	    }
	    else if (field_type==String.class)
	    {
		return (String)object;
	    }
	    else if (field_type==Class.class)
	    {
		return ((Class<?>)object).getCanonicalName();
	    }
	    else if (field_type==Date.class)
	    {
		return object.toString();
	    }
	    else if (field_type==File.class)
	    {
		return object.toString();
	    }
	    else if (field_type==URL.class)
	    {
		return object.toString();
	    }
	    else if (field_type==URI.class)
	    {
		return object.toString();
	    }
	    else if (field_type==LocalTime.class)
	    {
		return object.toString();		
	    }
	    else if (field_type==Level.class)
	    {
		return object.toString();		
	    }
	    else if (field_type==InetAddress.class || field_type==Inet4Address.class || field_type==Inet6Address.class)
	    {
		return object.toString();
	    }
	    else if (field_type==InetSocketAddress.class)
	    {
		InetSocketAddress isa=(InetSocketAddress)object;
		return isa.getAddress().toString()+":"+isa.getPort();
	    }
	    else 
		return null;
    }

    
    
}

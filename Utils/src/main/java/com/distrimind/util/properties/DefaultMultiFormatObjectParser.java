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

package com.distrimind.util.properties;

import java.io.File;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URL;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.TimeZone;
import java.util.logging.Level;
import java.util.regex.Pattern;

import javax.lang.model.SourceVersion;

import com.distrimind.util.crypto.*;
import org.apache.commons.codec.binary.Base64;

import com.distrimind.util.AbstractDecentralizedID;
import com.distrimind.util.Bits;
import com.distrimind.util.crypto.ASymmetricAuthenticatedSignatureType;


/**
 * 
 * @author Jason Mahdjoub
 * @version 2.0
 * @since Utils 1.0
 */
public class DefaultMultiFormatObjectParser extends AbstractMultiFormatObjectParser {



	/**
	 * 
	 */
	private static final long serialVersionUID = -6853594945240574230L;

	private static final Class<?>[] supportedClasses=new Class<?>[] {
		Boolean.class,
		Byte.class,
		Short.class,
		Integer.class,
		Long.class,
		Float.class,
		Double.class,
		Character.class,
		String.class,
		Class.class,
		Date.class,
		File.class,
		URL.class,
		URI.class,
		Level.class,
		InetAddress.class,
		Inet4Address.class,
		byte[].class,
		short[].class,
		char[].class,
		int[].class,
		long[].class,
		float[].class,
		double[].class,
		boolean[].class,
		Inet6Address.class,
		InetSocketAddress.class,
		SourceVersion.class,
		ASymmetricEncryptionType.class,
		MessageDigestType.class,
		SymmetricEncryptionType.class,
		ASymmetricAuthenticatedSignatureType.class,
		SymmetricSecretKey.class,
		ASymmetricPrivateKey.class,
		ASymmetricPublicKey.class,
		ASymmetricKeyPair.class

	};
	private static final Class<?>[] supportedMultiClasses=new Class<?>[] {
		AbstractDecentralizedID.class, MultiFormatProperties.class,Enum.class,Calendar.class
	};
	private SimpleDateFormat getSimpleDateFormat()
	{
		return new SimpleDateFormat(simpleDataFormats[0]);
	}
	private static final String[] simpleDataFormats =new String[]{
			"yyyy-MM-dd HH:mm:ss.SSS",
			"yyyy-MM-dd HH:mm:ss",
			"yyyy-MM-dd HH:mm",
			"yyyy-MM-dd",
			"HH:mm:ss.SSS",
			"HH:mm:ss",
			"HH:mm",
	};

	private static final Pattern beginWithYearPattern=Pattern.compile("^[0-9]{4}-[0-9]{2}-[0-9]{2}.*");




	private SimpleDateFormat getSimpleDateFormatForRead(int length)
	{
		for (String s : simpleDataFormats)
			if (s.length()==length)
				return new SimpleDateFormat(s);
		return null;
	}

	@Override
	public Class<?>[] getSupportedClasses()
	{
		return supportedClasses;
	}
	
	@Override
	public Class<?>[] getSupportedMultiClasses()
	{
		return supportedMultiClasses;
	}
	
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public String convertObjectToString(Class<?> field_type, Object object)  {
		if (field_type == byte[].class) {
			
			return Base64.encodeBase64URLSafeString((byte[]) object);
		} else if (field_type == char[].class) {
			return new String((char[]) object);
		} else if (field_type == int[].class) {
			if (object == null)
				return null;
			int[] tab = (int[]) object;
			int s = Integer.SIZE / 8;
			byte[] btab = new byte[tab.length * s];
			for (int i = 0; i < tab.length; i++)
				Bits.putInt(btab, i * s, tab[i]);
			return Base64.encodeBase64URLSafeString(btab);
		} else if (field_type == short[].class) {
			if (object == null)
				return null;
			short[] tab = (short[]) object;
			int s = Short.SIZE / 8;
			byte[] btab = new byte[tab.length * s];
			for (int i = 0; i < tab.length; i++)
				Bits.putShort(btab, i * s, tab[i]);
			return Base64.encodeBase64URLSafeString(btab);
		} else if (field_type == float[].class) {
			if (object == null)
				return null;
			float[] tab = (float[]) object;
			int s = Float.SIZE / 8;
			byte[] btab = new byte[tab.length * s];
			for (int i = 0; i < tab.length; i++)
				Bits.putFloat(btab, i * s, tab[i]);
			return Base64.encodeBase64URLSafeString(btab);
		} else if (field_type == double[].class) {
			if (object == null)
				return null;
			double[] tab = (double[]) object;
			int s = Double.SIZE / 8;
			byte[] btab = new byte[tab.length * s];
			for (int i = 0; i < tab.length; i++)
				Bits.putDouble(btab, i * s, tab[i]);
			return Base64.encodeBase64URLSafeString(btab);
		} else if (field_type == long[].class) {
			if (object == null)
				return null;
			long[] tab = (long[]) object;
			int s = Double.SIZE / 8;
			byte[] btab = new byte[tab.length * s];
			for (int i = 0; i < tab.length; i++)
				Bits.putLong(btab, i * s, tab[i]);
			return Base64.encodeBase64URLSafeString(btab);
		} else if (field_type == boolean[].class) {
			if (object == null)
				return null;
			boolean[] tab = (boolean[]) object;
			byte[] btab = new byte[tab.length];
			for (int i = 0; i < tab.length; i++)
				btab[i] = tab[i] ? (byte) 1 : (byte) 0;
			return Base64.encodeBase64URLSafeString(btab);
		} else if (field_type == Boolean.class) {
			return object.toString();
		} else if (field_type == Byte.class) {
			return object.toString();
		} else if (field_type == Short.class) {
			return object.toString();
		} else if (field_type == Integer.class) {
			return object.toString();
		} else if (field_type == Long.class) {
			return object.toString();
		} else if (field_type == Float.class) {
			return object.toString();
		} else if (field_type == Double.class) {
			return object.toString();
		} else if (field_type == Character.class) {
			return object.toString();
		} else if (field_type == String.class) {
			return (String) object;
		} else if (field_type == Class.class) {
			return ((Class<?>) object).getCanonicalName();
		} else if (field_type == Date.class) {
			return toString((Date) object);
		} else if (Calendar.class.isAssignableFrom(field_type)) {
			SimpleDateFormat calendarDateFormat=getSimpleDateFormat();
			calendarDateFormat.setTimeZone(((Calendar)object).getTimeZone());
			return getSimpleDateFormat().format(((Calendar)object).getTime())+" "+calendarDateFormat.getTimeZone().getID();
			//return toString(((Calendar) object).getTime()) + ";" + ((Calendar) object).getTimeZone().getID();
		} else if (field_type == File.class) {
			return object.toString();
		} else if (field_type == URL.class) {
			return object.toString();
		} else if (field_type == URI.class) {
			return object.toString();
		} else if (field_type == Level.class) {
			return object.toString();
		} else if (field_type == InetAddress.class || field_type == Inet4Address.class
				|| field_type == Inet6Address.class) {
			InetAddress ia = (InetAddress) object;
			return ia.getHostAddress();
		} else if (field_type == InetSocketAddress.class) {
			InetSocketAddress isa = (InetSocketAddress) object;
			return isa.getAddress().getHostAddress() + ";" + isa.getPort();
		} else if (field_type == SourceVersion.class) {
			return object.toString();
		} else if (field_type == ASymmetricEncryptionType.class) {
			return object.toString();
		} else if (field_type == SymmetricEncryptionType.class) {
			return object.toString();
		} else if (field_type == ASymmetricAuthenticatedSignatureType.class) {
			return object.toString();
		} else if (field_type == MessageDigestType.class) {
			return object.toString();
		}
		/*
		 * else if (field_type==SymmetricSecretKeyType.class) { return
		 * object.toString(); }
		 */
		else if (field_type == SymmetricSecretKey.class) {
			return object.toString();
		} else if (field_type == ASymmetricPrivateKey.class) {
			return object.toString();
		} else if (field_type == ASymmetricPublicKey.class) {
			return object.toString();
		} else if (field_type == ASymmetricKeyPair.class) {
			return object.toString();
		} else if (field_type.isEnum()) {
			return ((Enum<?>) object).name();
		} else if (AbstractDecentralizedID.class.isAssignableFrom(field_type))
			return object.toString();
		else
			return null;
	}



	/**
	 * {@inheritDoc}
	 */
	@Override
	public Object convertStringToObject(Class<?> field_type, String nodeValue) throws Exception {
		if (nodeValue == null)
			return null;
		nodeValue = nodeValue.trim();
		if (field_type == byte[].class) {
			return Base64.decodeBase64(nodeValue);
		} else if (field_type == char[].class) {
			return nodeValue.toCharArray();
		} else if (field_type == int[].class) {
			byte[] btab = Base64.decodeBase64(nodeValue);
			int s = Integer.SIZE / 8;
			if (btab.length % s != 0)
				throw new PropertiesParseException("Invalid tab data");
			int[] tab = new int[btab.length / s];
			for (int i = 0; i < tab.length; i++)
				tab[i] = Bits.getInt(btab, i * s);
			return tab;
		} else if (field_type == float[].class) {
			byte[] btab = Base64.decodeBase64(nodeValue);
			int s = Float.SIZE / 8;
			if (btab.length % s != 0)
				throw new PropertiesParseException("Invalid tab data");
			float[] tab = new float[btab.length / s];
			for (int i = 0; i < tab.length; i++)
				tab[i] = Bits.getFloat(btab, i * s);
			return tab;
		} else if (field_type == double[].class) {
			byte[] btab = Base64.decodeBase64(nodeValue);
			int s = Double.SIZE / 8;
			if (btab.length % s != 0)
				throw new PropertiesParseException("Invalid tab data");
			double[] tab = new double[btab.length / s];
			for (int i = 0; i < tab.length; i++)
				tab[i] = Bits.getDouble(btab, i * s);
			return tab;
		} else if (field_type == short[].class) {
			byte[] btab = Base64.decodeBase64(nodeValue);
			int s = Short.SIZE / 8;
			if (btab.length % s != 0)
				throw new PropertiesParseException("Invalid tab data");
			short[] tab = new short[btab.length / s];
			for (int i = 0; i < tab.length; i++)
				tab[i] = Bits.getShort(btab, i * s);
			return tab;
		} else if (field_type == long[].class) {
			byte[] btab = Base64.decodeBase64(nodeValue);
			int s = Long.SIZE / 8;
			if (btab.length % s != 0)
				throw new PropertiesParseException("Invalid tab data");
			long[] tab = new long[btab.length / s];
			for (int i = 0; i < tab.length; i++)
				tab[i] = Bits.getLong(btab, i * s);
			return tab;
		} else if (field_type == boolean[].class) {
			byte[] btab = Base64.decodeBase64(nodeValue);
			boolean[] tab = new boolean[btab.length];
			for (int i = 0; i < tab.length; i++)
				tab[i] = btab[i] != 0;
			return tab;
		} else if (field_type == Boolean.class) {
			return Boolean.parseBoolean(nodeValue);
		} else if (field_type == Byte.class) {
			return Byte.parseByte(nodeValue);
		} else if (field_type == Short.class) {
			return Short.parseShort(nodeValue);
		} else if (field_type == Integer.class) {
			return Integer.parseInt(nodeValue);
		} else if (field_type == Long.class) {
			return Long.parseLong(nodeValue);
		} else if (field_type == Float.class) {
			return Float.parseFloat(nodeValue);
		} else if (field_type == Double.class) {
			return Double.parseDouble(nodeValue);
		} else if (field_type == Character.class) {
			return nodeValue.charAt(0);
		} else if (field_type == String.class) {
			return nodeValue;
		} else if (field_type == Class.class) {
			return Class.forName(nodeValue);
		} else if (field_type == Date.class) {
			return parseDateString(nodeValue);
		} else if (Calendar.class.isAssignableFrom(field_type)) {
			nodeValue=nodeValue.trim();
			int i=nodeValue.lastIndexOf(' ');
			SimpleDateFormat calendarDateFormat;
			TimeZone tz=null;
			boolean timeZonePresent=i>0;
			if (timeZonePresent)
				timeZonePresent=nodeValue.lastIndexOf(' ', i)>0 || beginWithYearPattern.matcher(nodeValue).matches();
			if (timeZonePresent)
			{
				calendarDateFormat=getSimpleDateFormatForRead(i);
				if (calendarDateFormat!=null) {
					tz = TimeZone.getTimeZone(nodeValue.substring(i + 1));
					nodeValue = nodeValue.substring(0, i);
				}
			}
			else {
				calendarDateFormat=getSimpleDateFormatForRead(nodeValue.length());
				tz=TimeZone.getTimeZone("GMT");
			}
			if (calendarDateFormat==null)
				throw new PropertiesParseException("Invalid calendar : "+nodeValue);
			calendarDateFormat.setTimeZone(tz);
			Calendar c = Calendar.getInstance();
			c.setTimeZone(tz);
			c.setTime(calendarDateFormat.parse(nodeValue));
			return c;

		} else if (field_type == File.class) {
			return new File(nodeValue);
		} else if (field_type == URL.class) {
			return new URL(nodeValue);
		} else if (field_type == URI.class) {
			return new URI(nodeValue);
		} else if (field_type == Level.class) {
			return Level.parse(nodeValue);
		} else if (field_type == InetAddress.class) {
			return InetAddress.getByName(nodeValue);
		} else if (field_type == Inet4Address.class) {
			InetAddress res = InetAddress.getByName(nodeValue);
			if (!(res instanceof Inet4Address))
				return Void.TYPE;
			else
				return res;
		} else if (field_type == Inet6Address.class) {
			InetAddress res = InetAddress.getByName(nodeValue);
			if (!(res instanceof Inet6Address))
				return Void.TYPE;
			else
				return res;
		} else if (field_type == InetSocketAddress.class) {
			String[] split = nodeValue.split(";");
			if (split.length != 2)
				return Void.TYPE;
			return new InetSocketAddress(InetAddress.getByName(split[0]), Integer.parseInt(split[1]));
		} else if (field_type == SourceVersion.class) {
			return SourceVersion.valueOf(nodeValue);
		} else if (field_type == ASymmetricEncryptionType.class) {
			return ASymmetricEncryptionType.valueOf(nodeValue);
		} else if (field_type == SymmetricEncryptionType.class) {
			return SymmetricEncryptionType.valueOf(nodeValue);
		} else if (field_type == ASymmetricAuthenticatedSignatureType.class) {
			return ASymmetricAuthenticatedSignatureType.valueOf(nodeValue);
		} else if (field_type == MessageDigestType.class) {
			return MessageDigestType.valueOf(nodeValue);
		}
		/*
		 * else if (field_type==SymmetricSecretKeyType.class) { return
		 * SymmetricSecretKeyType.valueOf(nodeValue); }
		 */
		else if (field_type == SymmetricSecretKey.class) {
			return SymmetricSecretKey.valueOf(nodeValue);
		} else if (field_type == ASymmetricPrivateKey.class) {
			return ASymmetricPrivateKey.valueOf(nodeValue);
		} else if (field_type == ASymmetricPublicKey.class) {
			return ASymmetricPublicKey.valueOf(nodeValue);
		} else if (field_type == ASymmetricKeyPair.class) {
			return ASymmetricKeyPair.valueOf(nodeValue);
		} else if (field_type.isEnum()) {
			for (Enum<?> e : (Enum<?>[]) field_type.getEnumConstants()) {
				if (e.name().equals(nodeValue))
					return e;
			}
			return null;
		} else if (AbstractDecentralizedID.class.isAssignableFrom(field_type))
			return AbstractDecentralizedID.valueOf(nodeValue);

		return Void.TYPE;
	}



	/*SimpleDateFormat getSimpleDateFormat() {
		SimpleDateFormat format = new SimpleDateFormat("yyyy:MM:dd HH:mm:ss:SSSS z");
		format.setTimeZone(TimeZone.getTimeZone("GMT"));
		return format;
	}*/

	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean isValid(Class<?> field_type) {
		if (field_type.isEnum() || field_type.isPrimitive())
			return true;
		for (Class<?> c : getSupportedClasses())
			if (c==field_type)
				return true;
		
		for (Class<?> c : getSupportedMultiClasses())
			if (c.isAssignableFrom(field_type))
				return true;
		return false;
	}
	

	Date parseDateString(String d) {
		return new Date(Long.parseLong(d));
		// return getSimpleDateFormat().parse(d);

	}

	String toString(Date d) {
		// return getSimpleDateFormat().format(d);
		return Long.toString(d.getTime());
	}

}

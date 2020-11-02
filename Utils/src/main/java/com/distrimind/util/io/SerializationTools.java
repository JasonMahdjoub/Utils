/*
 * MadKitLanEdition (created by Jason MAHDJOUB (jason.mahdjoub@distri-mind.fr)) Copyright (c)
 * 2015 is a fork of MadKit and MadKitGroupExtension. 
 * 
 * Copyright or © or Copr. Jason Mahdjoub, Fabien Michel, Olivier Gutknecht, Jacques Ferber (1997)
 * 
 * jason.mahdjoub@distri-mind.fr
 * fmichel@lirmm.fr
 * olg@no-distance.net
 * ferber@lirmm.fr
 * 
 * This software is a computer program whose purpose is to
 * provide a lightweight Java library for designing and simulating Multi-Agent Systems (MAS).
 * This software is governed by the CeCILL-C license under French law and
 * abiding by the rules of distribution of free software.  You can  use,
 * modify and/ or redistribute the software under the terms of the CeCILL-C
 * license as circulated by CEA, CNRS and INRIA at the following URL
 * "http://www.cecill.info".
 * As a counterpart to the access to the source code and  rights to copy,
 * modify and redistribute granted by the license, users are provided only
 * with a limited warranty  and the software's author,  the holder of the
 * economic rights,  and the successive licensors  have only  limited
 * liability.
 * 
 * In this respect, the user's attention is drawn to the risks associated
 * with loading,  using,  modifying and/or developing or reproducing the
 * software by the user in light of its specific status of free software,
 * that may mean  that it is complicated to manipulate,  and  that  also
 * therefore means  that it is reserved for developers  and  experienced
 * professionals having in-depth computer knowledge. Users are therefore
 * encouraged to load and test the software's suitability as regards their
 * requirements in conditions enabling the security of their systems and/or
 * data to be ensured and,  more generally, to use and operate it in the
 * same conditions as regards security.
 * The fact that you are presently reading this means that you have had
 * knowledge of the CeCILL-C license and that you accept its terms.
 */
package com.distrimind.util.io;


import com.distrimind.util.*;
import com.distrimind.util.crypto.*;
import com.distrimind.util.harddrive.FilePermissions;

import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Modifier;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.*;
import java.util.concurrent.*;


/**
 * 
 * @author Jason Mahdjoub
 * @since Utils 4.5.0
 * @version 3.0
 * 
 */

public class SerializationTools {
	private static final int MAX_CHAR_BUFFER_SIZE=Short.MAX_VALUE*5;
	
	static void writeString(final SecuredObjectOutputStream oos, String s, int sizeMax, boolean supportNull) throws IOException
	{

		if (s==null)
		{
			if (!supportNull)
				throw new IOException();
			writeSize(oos, true, 0, sizeMax);
			return;
			
		}
		writeSize(oos, false, s.length(), sizeMax);
		oos.writeChars(s);
	}
	private static final Object stringLocker=new Object();
	
	private static char[] chars=null;

	static String readString(final SecuredObjectInputStream ois, int sizeMax, boolean supportNull) throws IOException
	{
		int size=readSize(ois, sizeMax);
		if (size==-1)
		{
			if (!supportNull)
				throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN);
			return null;
		}
		if (sizeMax<MAX_CHAR_BUFFER_SIZE)
		{
			synchronized(stringLocker)
			{
				if (chars==null || chars.length<sizeMax)
					chars=new char[sizeMax];
				for (int i=0;i<size;i++)
					chars[i]=ois.readChar();
				return new String(chars, 0, size);
			}
		}
		else
		{
			char []chars=new char[sizeMax];
			for (int i=0;i<size;i++)
				chars[i]=ois.readChar();
			return new String(chars, 0, size);
			
		}
	}
	
	@SuppressWarnings("SameParameterValue")
	static void writeBytes(final SecuredObjectOutputStream oos, byte[] tab, int sizeMax, boolean supportNull) throws IOException
	{
		writeBytes(oos, tab, 0, tab==null?0:tab.length, sizeMax, supportNull);
	}
	@SuppressWarnings("SameParameterValue")
	static void writeBytes(final SecuredObjectOutputStream oos, byte[] tab, int off, int size, int sizeMax, boolean supportNull) throws IOException
	{

		if (tab==null)
		{
			if (!supportNull)
				throw new IOException();
			writeSize(oos, true, 0, sizeMax);
			return;
			
		}
		writeSize(oos, false, size, sizeMax);
		oos.write(tab, off, size);
	}
	@SuppressWarnings("SameParameterValue")
	static void writeBytes2D(final SecuredObjectOutputStream oos, byte[][] tab, int sizeMax1, int sizeMax2, boolean supportNull1, boolean supportNull2) throws IOException
	{
		writeBytes2D(oos, tab, 0, tab==null?0:tab.length, sizeMax1, sizeMax2, supportNull1, supportNull2);
	}
	@SuppressWarnings("SameParameterValue")
	static void writeBytes2D(final SecuredObjectOutputStream oos, byte[][] tab, int off, int size, int sizeMax1, int sizeMax2, boolean supportNull1, boolean supportNull2) throws IOException
	{

		if (tab==null)
		{
			if (!supportNull1)
				throw new IOException();
			writeSize(oos, true, 0, sizeMax1);
			return;
			
		}
		writeSize(oos, false, size, sizeMax1);
		for (int i=off;i<size;i++) {
			byte[] b=tab[i];
			SerializationTools.writeBytes(oos, b, 0, b==null?0:b.length, sizeMax2, supportNull2);
		}
	}
	@SuppressWarnings("SameParameterValue")
	static byte[][] readBytes2D(final SecuredObjectInputStream ois, int sizeMax1, int sizeMax2, boolean supportNull1, boolean supportNull2) throws IOException
	{
		int size=readSize(ois, sizeMax1);

		if (size==-1)
		{
			if (!supportNull1)
				throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN);
			return null;
		}

		byte [][]tab=new byte[size][];
		for (int i=0;i<size;i++)
			tab[i]=readBytes(ois, supportNull2, null, 0, sizeMax2);
		
		
		return tab;
		
	}
	@SuppressWarnings("SameParameterValue")
	static byte[] readBytes(final SecuredObjectInputStream ois, boolean supportNull, byte[] tab, int off, int sizeMax) throws IOException
	{

		int size=readSize(ois, sizeMax );
		if (size==-1)
		{
			if (!supportNull)
				throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN);
			return null;
		}
		if (tab==null) {
			tab = new byte[size];
			off = 0;
		}


		ois.readFully(tab, off, size);
		
		return tab;
		
	}
	

	public static final int MAX_BIG_INTEGER_SIZE=Short.MAX_VALUE;
	@SuppressWarnings("SameParameterValue")
	static void writeKey(final SecuredObjectOutputStream oos, AbstractKey key, boolean supportNull) throws IOException
	{
		if (supportNull)
			oos.writeBoolean(key!=null);

		if (key==null)
		{
			if (!supportNull)
				throw new IOException();

			return;
			
		}

		writeBytes(oos, key.encode(), AbstractKey.MAX_KEY_SIZE_IN_BYTES, false);
	}

	@SuppressWarnings("SameParameterValue")
	static AbstractKey readKey(final SecuredObjectInputStream in, boolean supportNull) throws IOException
	{
		if (!supportNull || in.readBoolean())
		{
			byte[] k=readBytes(in, false, null, 0, AbstractKey.MAX_KEY_SIZE_IN_BYTES);
			try
			{
				if (k == null)
					throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN);
				return AbstractKey.decode(k);
			}
			catch(Exception e)
			{
				throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN);
			}
		}
		else
		{
			return null;
		}
	}
	
	
	@SuppressWarnings("SameParameterValue")
	static void writeKeyPair(final SecuredObjectOutputStream oos, AbstractKeyPair<?, ?> keyPair, boolean supportNull) throws IOException
	{
		if (supportNull)
			oos.writeBoolean(keyPair!=null);

		if (keyPair==null)
		{
			if (!supportNull)
				throw new IOException();

			return;
			
		}


		writeBytes(oos, keyPair.encode(), AbstractKey.MAX_KEY_PAIR_SIZE_IN_BYTES, false);
	}

	@SuppressWarnings("SameParameterValue")
	static AbstractKeyPair<?, ?> readKeyPair(final SecuredObjectInputStream in, boolean supportNull) throws IOException
	{
		if (!supportNull || in.readBoolean())
		{
			byte[] k=readBytes(in, false, null, 0, AbstractKey.MAX_KEY_PAIR_SIZE_IN_BYTES);
			try
			{
				if (k==null)
					throw new MessageExternalizationException(Integrity.FAIL);
				return AbstractKeyPair.decode(k);
			}
			catch(Exception e)
			{
				throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN);
			}
		}
		else
		{
			return null;
		}
	}
	@SuppressWarnings("SameParameterValue")
	static void writeObjects(final SecuredObjectOutputStream oos, Object[] tab, int sizeMax, boolean supportNull) throws IOException
	{

		if (tab==null)
		{
			if (!supportNull)
				throw new IOException();
			writeSize(oos, true, 0, sizeMax);
			return;

		}
		writeSize(oos, false, tab.length, sizeMax);
		sizeMax-=tab.length;
		for (Object o : tab)
		{
			writeObject(oos, o, sizeMax, true);
		}
	}
	static void writeCollection(final SecuredObjectOutputStream oos, Collection<?> collection, int sizeMax, boolean supportNull, boolean supportNullCollectionElements) throws IOException
	{

		if (collection==null)
		{
			if (!supportNull)
				throw new IOException();
			writeSize(oos, true, 0, sizeMax);
			return;

		}
		Class<?> lClass=collection.getClass();
		try {
			if (!Modifier.isPublic(lClass.getModifiers())) {
				if (List.class.isAssignableFrom(lClass)) {
					if (RandomAccess.class.isAssignableFrom(lClass))
						lClass = ArrayList.class;
					else
						lClass = LinkedList.class;
				}
				else if (Set.class.isAssignableFrom(lClass))
					lClass=HashSet.class;
				else
					throw new IOException("The collection " + lClass + " must be a public class");
			}
			else {
				Constructor<?> c = lClass.getDeclaredConstructor();
				if (!Modifier.isPublic(c.getModifiers()))
					throw new IOException("The collection " + lClass + " must have a default public constructor");
			}

		} catch (NoSuchMethodException e) {
			throw new IOException(e);
		}

		int i;
		for (i=0;i<collectionsClasses.length;i++)
		{
			if (collectionsClasses[i].equals(lClass))
				break;
		}
		if (i<collectionsClasses.length) {
			writeSize(oos, false, collection.size(), sizeMax);
			oos.writeUnsignedByte(i);
			sizeMax-=collection.size();
			for (Object o : collection)
			{
				writeObject(oos, o, sizeMax, supportNullCollectionElements);
			}
		}
		else {
			throw new IOException("Invalid class "+lClass);
		}



	}
	@SuppressWarnings({"rawtypes", "unchecked"})
	static Collection readCollection(final SecuredObjectInputStream ois, int sizeMax, boolean supportNull, boolean supportNullCollectionElements) throws IOException, ClassNotFoundException
	{
		int size=readSize(ois, sizeMax);
		if (size==-1)
		{
			if (!supportNull)
				throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN);
			return null;
		}

		int cIndex=ois.readUnsignedByte();

		if (cIndex<0 || cIndex>collectionsClasses.length)
			throw new IOException("Invalid class index : "+cIndex);
		Class<? extends Collection<?>> cClass=collectionsClasses[cIndex];
		try {
			Collection collection=cClass.getDeclaredConstructor().newInstance();

			sizeMax-=size;
			for (int i=0;i<size;i++)
			{
				collection.add(readObject(ois, sizeMax, supportNullCollectionElements));
			}

			return collection;
		} catch (InstantiationException | IllegalAccessException | InvocationTargetException | NoSuchMethodException e) {
			throw new IOException(e);
		}
	}
	static void writeMap(final SecuredObjectOutputStream oos, Map<?, ?> map, int sizeMax, boolean supportNull, boolean supportNullMapKey, boolean supportNullMapValue) throws IOException
	{


		if (map==null)
		{
			if (!supportNull)
				throw new IOException();
			writeSize(oos, true, 0, sizeMax);
			return;

		}
		Class<?> mClass=map.getClass();
		try {
			if (!Modifier.isPublic(mClass.getModifiers()))
				throw new IOException("The map "+mClass+" must be a public class");
			Constructor<?> c=mClass.getDeclaredConstructor();
			if (!Modifier.isPublic(c.getModifiers()))
				throw new IOException("The map "+mClass+" must have a default public constructor");

		} catch (NoSuchMethodException e) {
			throw new IOException(e);
		}

		int i;
		for (i=0;i<mapClasses.length;i++)
		{
			if (mapClasses[i].equals(mClass))
				break;
		}
		if (i<mapClasses.length) {
			writeSize(oos, false, map.size(), sizeMax);
			oos.writeUnsignedByte(i);
			sizeMax-=map.size();
			for (Map.Entry<?, ?> e : map.entrySet())
			{
				writeObject(oos, e.getKey(), sizeMax, supportNullMapKey);
				writeObject(oos, e.getValue(), sizeMax, supportNullMapValue);
			}
		}
		else {
			throw new IOException("Invalid class "+mClass);
		}


	}
	@SuppressWarnings({"rawtypes", "unchecked"})
	static Map readMap(final SecuredObjectInputStream ois, int sizeMax, boolean supportNull, boolean supportNullMapKey, boolean supportNullMapValue) throws IOException, ClassNotFoundException
	{
		int size=readSize(ois, sizeMax);
		if (size==-1)
		{
			if (!supportNull)
				throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN);
			return null;
		}

		int cIndex=ois.readUnsignedByte();

		if (cIndex<0 || cIndex>mapClasses.length)
			throw new IOException("Invalid class index : "+cIndex);
		Class<? extends Map<?, ?>> cClass=mapClasses[cIndex];
		try {
			Map map=cClass.getDeclaredConstructor().newInstance();

			sizeMax-=size;
			for (int i=0;i<size;i++)
			{
				Object k=readObject(ois, sizeMax, supportNullMapKey);
				Object v=readObject(ois, sizeMax, supportNullMapValue);
				map.put(k,v);
			}

			return map;
		} catch (InstantiationException | IllegalAccessException | InvocationTargetException | NoSuchMethodException e) {
			throw new IOException(e);
		}
	}
	static void writeBigDecimal(final SecuredObjectOutputStream oos, BigDecimal bigDecimal, boolean supportNull) throws IOException {
		if (supportNull)
			oos.writeBoolean(bigDecimal!=null);

		if (bigDecimal==null)
		{
			if (!supportNull)
				throw new IOException();

			return;

		}
		oos.writeInt(bigDecimal.scale());
		writeBytes(oos, bigDecimal.unscaledValue().toByteArray(), MAX_BIG_INTEGER_SIZE, false);
	}
	static BigDecimal readBigDecimal(final SecuredObjectInputStream in, boolean supportNull) throws IOException
	{
		if (!supportNull || in.readBoolean())
		{
			int scale=in.readInt();
			byte[] bd=readBytes(in, false, null, 0, MAX_BIG_INTEGER_SIZE);
			try
			{
				if (bd == null)
					throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN);
				return new BigDecimal(new BigInteger(bd), scale);
			}
			catch(Exception e)
			{
				throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN);
			}
		}
		else
		{
			return null;
		}
	}
	static void writeBigInteger(final SecuredObjectOutputStream oos, BigInteger bigInteger, boolean supportNull) throws IOException {
		if (supportNull)
			oos.writeBoolean(bigInteger!=null);

		if (bigInteger==null)
		{
			if (!supportNull)
				throw new IOException();

			return;

		}
		writeBytes(oos, bigInteger.toByteArray(), MAX_BIG_INTEGER_SIZE, false);
	}
	static BigInteger readBigInteger(final SecuredObjectInputStream in, boolean supportNull) throws IOException
	{
		if (!supportNull || in.readBoolean())
		{
			byte[] bd=readBytes(in, false, null, 0, MAX_BIG_INTEGER_SIZE);
			try
			{
				if (bd == null)
					throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN);
				return new BigInteger(bd);
			}
			catch(Exception e)
			{
				throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN);
			}
		}
		else
		{
			return null;
		}
	}

	@SuppressWarnings("unchecked")
	private static final Class<? extends Collection<?>>[] collectionsClasses=new Class[]{ArrayList.class,
			LinkedList.class,
			Stack.class,
			Vector.class,
			HashSet.class,
			TreeSet.class,
			EnumSet.class,
			LinkedHashSet.class,
			ConcurrentSkipListSet.class,
			CopyOnWriteArraySet.class,
			ArrayBlockingQueue.class,
			ArrayDeque.class,
			ConcurrentLinkedQueue.class,
			ConcurrentLinkedDeque.class,
			DelayQueue.class,
			LinkedBlockingQueue.class,
			LinkedBlockingDeque.class,
			LinkedTransferQueue.class,
			PriorityBlockingQueue.class,
			PriorityQueue.class,
			SynchronousQueue.class};
	@SuppressWarnings("unchecked")
	private static final Class<? extends Map<?, ?>>[] mapClasses=new Class[]{
			HashMap.class,
			ConcurrentHashMap.class,
			ConcurrentSkipListMap.class,
			EnumMap.class,
			Hashtable.class,
			LinkedHashMap.class,
			Properties.class,
			IdentityHashMap.class,
			TreeMap.class,
			WeakHashMap.class};

	@SuppressWarnings("SameParameterValue")
	static Object[] readObjects(final SecuredObjectInputStream ois, int sizeMax, boolean supportNull) throws IOException, ClassNotFoundException
	{
		int size=readSize(ois, sizeMax);
		if (size==-1)
		{
			if (!supportNull)
				throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN);
			return null;
		}

		Object []tab=new Object[size];
		sizeMax-=tab.length;
		for (int i=0;i<size;i++)
		{
			tab[i]=readObject(ois, sizeMax, true);
		}

		return tab;

	}

	/*public static void writeExternalizableAndSizables(final SecuredObjectOutputStream oos, ExternalizableAndSizable[] tab, int sizeMaxBytes, boolean supportNull) throws IOException
	{
		if (tab==null)
		{
			if (!supportNull)
				throw new IOException();
			oos.writeInt(-1);
			return;

		}
		if (tab.length*4>sizeMaxBytes)
			throw new IOException();
		oos.writeInt(tab.length);
		int total=4;

		for (ExternalizableAndSizable o : tab)
		{
			writeExternalizableAndSizable(oos, o, true);
			total+=o.getInternalSerializedSize();

			if (total>=sizeMaxBytes)
				throw new IOException();
		}
	}*/

	@SuppressWarnings("SameParameterValue")
	static void writeExternalizables(final SecuredObjectOutputStream objectOutput, SecureExternalizable[] tab, int sizeMaxBytes, boolean supportNull) throws IOException
	{
		if (sizeMaxBytes<0)
			throw new IllegalArgumentException();

		if (tab==null)
		{
			if (!supportNull)
				throw new IOException();
			objectOutput.writeInt(-1);
			return;

		}
		if (tab.length*4>sizeMaxBytes)
			throw new IOException();
		objectOutput.writeInt(tab.length);
		int total=4;

		for (SecureExternalizable o : tab)
		{
			writeExternalizable(objectOutput, o, true);
			total+=o==null?0:getInternalSize(o.getClass().getName(), MAX_CLASS_LENGTH);
			total+=o==null?1:o.getInternalSerializedSize();

			if (total>=sizeMaxBytes)
				throw new IOException();
		}
	}


	/*public static ExternalizableAndSizable[] readExternalizableAndSizables(final SecuredObjectInputStream ois, int sizeMaxBytes, boolean supportNull) throws IOException, ClassNotFoundException
	{
		int size=ois.readInt();
		if (size==-1)
		{
			if (!supportNull)
				throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN);
			return null;
		}
		if (size<0 || size*4>sizeMaxBytes)
			throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN);

		ExternalizableAndSizable []tab=new ExternalizableAndSizable[size];
		sizeMaxBytes-=4;
		for (int i=0;i<size;i++)
		{
			Externalizable o=readExternalizableAndSizable(ois, true);
			if (!(o instanceof ExternalizableAndSizable))
				throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN);
			ExternalizableAndSizable s=(ExternalizableAndSizable)o;
			sizeMaxBytes-=s.getInternalSerializedSize();
			if (sizeMaxBytes<0)
				throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN);
			tab[i]=s;
		}

		return tab;

	}*/

	@SuppressWarnings("SameParameterValue")
	static SecureExternalizable[] readExternalizables(final SecuredObjectInputStream ois, int sizeMaxBytes, boolean supportNull) throws IOException, ClassNotFoundException
	{
		if (sizeMaxBytes<0)
			throw new IllegalArgumentException();

		int size=ois.readInt();
		if (size==-1)
		{
			if (!supportNull)
				throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN);
			return null;
		}
		if (size<0 || size*4>sizeMaxBytes)
			throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN);

		SecureExternalizable []tab=new SecureExternalizable[size];
		sizeMaxBytes-=4;
		for (int i=0;i<size;i++)
		{
			SecureExternalizableWithoutInnerSizeControl s=readExternalizable(ois, true);
			if (s!=null) {
				if (!(s instanceof SecureExternalizable))
					throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN);
				sizeMaxBytes -= ((SecureExternalizable)s).getInternalSerializedSize();
				if (sizeMaxBytes < 0)
					throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN);
			}
			tab[i]=(SecureExternalizable)s;
		}

		return tab;

	}
	public static int MAX_URL_LENGTH=8000;
	@SuppressWarnings("SameParameterValue")
	static void writeInetAddress(final SecuredObjectOutputStream oos, InetAddress inetAddress, boolean supportNull) throws IOException
	{
		if (supportNull)
			oos.writeBoolean(inetAddress!=null);

		if (inetAddress==null)
		{
			if (!supportNull)
				throw new IOException();

			return;

		}

		writeBytes(oos, inetAddress.getAddress(), 20, false);
	}
	@SuppressWarnings("SameParameterValue")
	static void writeDate(final SecuredObjectOutputStream oos, Date date, boolean supportNull) throws IOException
	{
		if (supportNull)
			oos.writeBoolean(date!=null);

		if (date==null)
		{
			if (!supportNull)
				throw new IOException();

			return;

		}
		oos.writeLong(date.getTime());
	}

	@SuppressWarnings("SameParameterValue")
	static void writeDecentralizedID(final SecuredObjectOutputStream oos, AbstractDecentralizedID id, boolean supportNull) throws IOException
	{
		if (supportNull)
			oos.writeBoolean(id!=null);

		if (id==null)
		{
			if (!supportNull)
				throw new IOException();

			return;

		}

		writeBytes(oos, id.encode(), 513, false);
	}
	@SuppressWarnings("SameParameterValue")
	static AbstractDecentralizedID readDecentralizedID(final SecuredObjectInputStream in, boolean supportNull) throws IOException
	{
		if (!supportNull || in.readBoolean())
		{
			try
			{
				return AbstractDecentralizedID.decode(Objects.requireNonNull(readBytes(in, false, null, 0, 513)));
			}
			catch(Exception e)
			{
				throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN);
			}
		}
		else
			return null;
	}

	@SuppressWarnings("SameParameterValue")
	static InetAddress readInetAddress(final SecuredObjectInputStream ois, boolean supportNull) throws IOException {
		if (!supportNull || ois.readBoolean())
		{
			byte[] address=readBytes(ois, false, null, 0, 20);
			try
			{
				if (address==null)
					throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN);

				return InetAddress.getByAddress(address);
			}
			catch(Exception e)
			{
				throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN, e);
			}
		}
		else
			return null;

	}
	@SuppressWarnings("SameParameterValue")
	static Date readDate(final SecuredObjectInputStream ois, boolean supportNull) throws IOException {
		if (!supportNull || ois.readBoolean())
		{
			return new Date(ois.readLong());
		}
		else
			return null;

	}

	@SuppressWarnings("SameParameterValue")
	static void writeInetSocketAddress(final SecuredObjectOutputStream oos, InetSocketAddress inetSocketAddress, boolean supportNull) throws IOException
	{
		if (supportNull)
			oos.writeBoolean(inetSocketAddress!=null);

		if (inetSocketAddress==null)
		{
			if (!supportNull)
				throw new IOException();

			return;

		}

		oos.writeInt(inetSocketAddress.getPort());
		writeInetAddress(oos, inetSocketAddress.getAddress(), false);
	}


	@SuppressWarnings("SameParameterValue")
	static InetSocketAddress readInetSocketAddress(final SecuredObjectInputStream ois, boolean supportNull) throws IOException {
		if (!supportNull || ois.readBoolean())
		{
			int port=ois.readInt();
			InetAddress ia=readInetAddress(ois, false);

			try
			{
				return new InetSocketAddress(ia, port);
			}
			catch(Exception e)
			{
				throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN, e);
			}
		}
		else
			return null;

	}
	@SuppressWarnings("SameParameterValue")
	static void writeEnum(final SecuredObjectOutputStream oos, Enum<?> e, boolean supportNull) throws IOException
	{
		if (e==null)
		{
			if (!supportNull)
				throw new IOException();
			oos.writeByte(0);
			return;

		}
		Class<?> clazz=e.getClass();
		Short id=identifiersPerEnums.get(clazz);
		if (id==null) {
			oos.writeByte(1);
			SerializationTools.writeString(oos, e.getClass().getName(), MAX_CLASS_LENGTH, false);
		}
		else
		{
			oos.writeByte(2);
			writeObjectCode(oos, id);
		}
		oos.writeInt(e.ordinal());
	}
	static void writeHybridKeyAgreementType(final SecuredObjectOutputStream oos, HybridKeyAgreementType e, @SuppressWarnings("SameParameterValue") boolean supportNull) throws IOException
	{
		if (supportNull)
			oos.writeBoolean(e!=null);
		if (e==null)
		{
			if (!supportNull)
				throw new IOException();

			return;

		}
		oos.writeInt(e.getNonPQCKeyAgreementType().ordinal());
		oos.writeInt(e.getPQCKeyAgreementType().ordinal());
	}
	static void writeHybridASymmetricEncryptionType(final SecuredObjectOutputStream oos, HybridASymmetricEncryptionType e, @SuppressWarnings("SameParameterValue") boolean supportNull) throws IOException
	{
		if (supportNull)
			oos.writeBoolean(e!=null);
		if (e==null)
		{
			if (!supportNull)
				throw new IOException();

			return;

		}
		oos.writeInt(e.getNonPQCASymmetricEncryptionType().ordinal());
		oos.writeInt(e.getPQCASymmetricEncryptionType().ordinal());
	}
	static void writeHybridASymmetricAuthenticatedSignatureType(final SecuredObjectOutputStream oos, HybridASymmetricAuthenticatedSignatureType e, @SuppressWarnings("SameParameterValue") boolean supportNull) throws IOException
	{
		if (supportNull)
			oos.writeBoolean(e!=null);
		if (e==null)
		{
			if (!supportNull)
				throw new IOException();

			return;

		}
		oos.writeInt(e.getNonPQCASymmetricAuthenticatedSignatureType().ordinal());
		oos.writeInt(e.getPQCASymmetricAuthenticatedSignatureType().ordinal());
	}
	public final static int MAX_CLASS_LENGTH=2048;


	@SuppressWarnings({"SameParameterValue", "unchecked"})
	static Enum<?> readEnum(final SecuredObjectInputStream ois, boolean supportNull) throws IOException, ClassNotFoundException
	{
		byte code=ois.readByte();
		if (!supportNull || code>0)
		{
			Class<? extends Enum<?>> clazz;
			if (code==2)
			{
				int id=readObjectCode(ois);
				id-=enumsStartIndex;
				if (id>=0 && id<enums.size()) {
					clazz = enums.get(id);
				}
				else
					throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN);
			}
			else if (code==1){
				String clazzString = SerializationTools.readString(ois, MAX_CLASS_LENGTH, false);

				Class<?> c = Class.forName(clazzString, false, ReflectionTools.getClassLoader());
				if (!c.isEnum())
					throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN);
				clazz=(Class<? extends Enum<?>>)c;
			}
			else
				throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN);
			int ordinal=ois.readInt();
			for (Enum<?> e : clazz.getEnumConstants())
			{
				if (e.ordinal()==ordinal)
					return e;
			}

			throw new MessageExternalizationException(Integrity.FAIL);
		}
		else
			return null;

	}
	static HybridKeyAgreementType readHybridKeyAgreementType(final SecuredObjectInputStream ois, @SuppressWarnings("SameParameterValue") boolean supportNull) throws IOException
	{
		if (!supportNull || ois.readBoolean())
		{
			int kao=ois.readInt();
			int pqckao=ois.readInt();
			KeyAgreementType ka=null;
			for (KeyAgreementType t : KeyAgreementType.values())
			{
				if (t.ordinal()==kao)
				{
					ka=t;
					break;
				}
			}
			if (ka==null)
				throw new MessageExternalizationException(Integrity.FAIL);
			KeyAgreementType pqcka=null;
			for (KeyAgreementType t : KeyAgreementType.values())
			{
				if (t.ordinal()==pqckao)
				{
					pqcka=t;
					break;
				}
			}
			if (pqcka==null)
				throw new MessageExternalizationException(Integrity.FAIL);
			try {
				return new HybridKeyAgreementType(ka, pqcka);
			}
			catch(Exception e)
			{
				throw new IOException(e);
			}
		}
		else
			return null;
	}
	static HybridASymmetricAuthenticatedSignatureType readHybridASymmetricAuthenticatedSignatureType(final SecuredObjectInputStream ois, @SuppressWarnings("SameParameterValue") boolean supportNull) throws IOException
	{
		if (!supportNull || ois.readBoolean())
		{
			int kao=ois.readInt();
			int pqckao=ois.readInt();
			ASymmetricAuthenticatedSignatureType ka=null;
			for (ASymmetricAuthenticatedSignatureType t : ASymmetricAuthenticatedSignatureType.values())
			{
				if (t.ordinal()==kao)
				{
					ka=t;
					break;
				}
			}
			if (ka==null)
				throw new MessageExternalizationException(Integrity.FAIL);
			ASymmetricAuthenticatedSignatureType pqcka=null;
			for (ASymmetricAuthenticatedSignatureType t : ASymmetricAuthenticatedSignatureType.values())
			{
				if (t.ordinal()==pqckao)
				{
					pqcka=t;
					break;
				}
			}
			if (pqcka==null)
				throw new MessageExternalizationException(Integrity.FAIL);
			try {
				return new HybridASymmetricAuthenticatedSignatureType(ka, pqcka);
			}
			catch(Exception e)
			{
				throw new IOException(e);
			}
		}
		else
			return null;
	}
	static HybridASymmetricEncryptionType readHybridASymmetricEncryptionType(final SecuredObjectInputStream ois, @SuppressWarnings("SameParameterValue") boolean supportNull) throws IOException
	{
		if (!supportNull || ois.readBoolean())
		{
			int kao=ois.readInt();
			int pqckao=ois.readInt();
			ASymmetricEncryptionType ka=null;
			for (ASymmetricEncryptionType t : ASymmetricEncryptionType.values())
			{
				if (t.ordinal()==kao)
				{
					ka=t;
					break;
				}
			}
			if (ka==null)
				throw new MessageExternalizationException(Integrity.FAIL);
			ASymmetricEncryptionType pqcka=null;
			for (ASymmetricEncryptionType t : ASymmetricEncryptionType.values())
			{
				if (t.ordinal()==pqckao)
				{
					pqcka=t;
					break;
				}
			}
			if (pqcka==null)
				throw new MessageExternalizationException(Integrity.FAIL);
			try {
				return new HybridASymmetricEncryptionType(ka, pqcka);
			}
			catch(Exception e)
			{
				throw new IOException(e);
			}
		}
		else
			return null;
	}

	/*public static void writeExternalizableAndSizable(final SecuredObjectOutputStream oos, Externalizable e, boolean supportNull) throws IOException
	{
		if (e==null)
		{
			if (!supportNull)
				throw new IOException();
			oos.writeBoolean(false);
			return;

		}
		Class<?> clazz=e.getClass();
		if (!ExternalizableAndSizable.class.isAssignableFrom(clazz) && !SystemMessage.class.isAssignableFrom(clazz))
			throw new IOException();

		if (oos.getClass()==oosClazz)
		{
			try
			{
				e=(Externalizable)invoke(replaceObject, oos, e);
				if (e!=null)
					clazz=e.getClass();
			}
			catch(Exception e2)
			{
				throw new IOException(e2);
			}
		}
		oos.writeBoolean(true);
		SerializationTools.writeString(oos, clazz.getName(), MAX_CLASS_LENGTH, false);
		if (e==null)
			throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN);
		e.writeExternal(oos);

	}*/

	@SuppressWarnings("SameParameterValue")
	static void writeClass(final SecuredObjectOutputStream objectOutput, Class<?> clazz, boolean supportNull, Class<?> rootClass) throws IOException {
		if (rootClass==null)
			rootClass=Object.class;
		if (clazz==null) {
			if (supportNull)
				objectOutput.writeByte(0);
			else
				throw new IOException();
		}
		else {
			if (!rootClass.isAssignableFrom(clazz))
				throw new IOException();
			Short id=identifiersPerClasses.get(clazz);
			if (id==null) {
				objectOutput.writeByte(1);
				SerializationTools.writeString(objectOutput, clazz.getName(), MAX_CLASS_LENGTH, supportNull);
			}
			else {
				objectOutput.writeByte(2);
				writeObjectCode(objectOutput, id);
			}
		}


	}
	private static void writeExternalizable(final SecuredObjectOutputStream objectOutput, SecureExternalizableWithoutInnerSizeControl e) throws IOException
	{
		if (e==null)
			throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN);


		e.writeExternal(objectOutput);
	}
	static void writeExternalizable(final SecuredObjectOutputStream objectOutput, SecureExternalizableWithoutInnerSizeControl e, boolean supportNull) throws IOException
	{
		if (supportNull)
			objectOutput.writeBoolean(e!=null);
		if (e==null)
		{
			if (!supportNull)
				throw new IOException();

			return;

		}
		e=objectOutput.getObjectResolver().replaceObject(e);
		if (e==null)
			throw new IOException();
		Class<?> clazz=e.getClass();

		writeClass(objectOutput, clazz, false, SecureExternalizableWithoutInnerSizeControl.class);
		writeExternalizable(objectOutput, e);

	}
	private static final HashMap<Class<?>, Constructor<?>> constructors=new HashMap<>();

	private static Constructor<?> getDefaultConstructor(final Class<?> clazz) throws NoSuchMethodException, SecurityException
	{
		synchronized(constructors)
		{
			Constructor<?> c=constructors.get(clazz);
			if (c==null)
			{
				final Constructor<?> cons=clazz.getDeclaredConstructor();
				c=AccessController.doPrivileged((PrivilegedAction<Constructor<?>>) () -> {

					cons.setAccessible(true);
					return cons;
				});
				constructors.put(clazz, c);
			}
			return c;
		}
	}






	/*public static Externalizable readExternalizableAndSizable(final SecuredObjectInputStream ois, boolean supportNull) throws IOException, ClassNotFoundException
	{
		if (ois.readBoolean())
		{
			String clazz=SerializationTools.readString(ois, MAX_CLASS_LENGTH, false);




			try
			{
				Class<?> c;
				boolean isOIS=ois.getClass()==oisClazz;
				if (isOIS)
					c= ((FilteredObjectInputStream)ois).resolveClass(clazz);
				else
					c= Class.forName(clazz, false, MadkitClassLoader.getSystemClassLoader());
				if (!ExternalizableAndSizable.class.isAssignableFrom(c) && !SystemMessage.class.isAssignableFrom(c))
					throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN);
				if (!isOIS)
					c= Class.forName(clazz, true, MadkitClassLoader.getSystemClassLoader());
				Constructor<?> cons=getDefaultConstructor(c);
				Externalizable res=(Externalizable)cons.newInstance();

				res.readExternal(ois);
				if (isOIS)
				{
					res=(Externalizable)invoke(resolveObject, ois, res);
				}
				return res;
			}
			catch(InvocationTargetException | NoSuchMethodException | IllegalAccessException | InstantiationException e)
			{
				throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN, e);
			}

		}
		else if (!supportNull)
			throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN);
		else
			return null;

	}*/

	@SuppressWarnings("unchecked")
	static <RT> Class<? extends RT> readClass(final SecuredObjectInputStream objectInput, boolean supportNull, Class<RT> rootClass) throws IOException, ClassNotFoundException {
		if (rootClass==null)
			throw new NullPointerException();
		byte code=objectInput.readByte();
		if (!supportNull || code>0)
		{
			Class<?> c;
			boolean doubleCheck = rootClass != Object.class;
			if (code==1) {
				String clazz = SerializationTools.readString(objectInput, MAX_CLASS_LENGTH, false);


				c = objectInput.getObjectResolver().resolveClass(clazz, !doubleCheck);
				if (doubleCheck) {
					if (!rootClass.isAssignableFrom(c))
						throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN, "rootClass : "+rootClass+" ; class="+c);
					c = Class.forName(clazz, true, ReflectionTools.getClassLoader());
				}
			}
			else if (code==2)
			{
				int id=readObjectCode(objectInput);
				id-=classesStartIndex;
				if (id>=0 && id<classes.size()) {
					c = classes.get(id);
				}
				else
					throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN);
				if (doubleCheck) {
					if (!rootClass.isAssignableFrom(c))
						throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN, "rootClass : "+rootClass+" ; class="+c);
				}
			}
			else
				throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN);

			return (Class<? extends RT>)c;
		}
		else
			return null;

	}
	private static SecureExternalizableWithoutInnerSizeControl readExternalizable(final SecuredObjectInputStream objectInput, Class<?> c) throws IOException, ClassNotFoundException
	{
		try
		{

			Constructor<?> cons=getDefaultConstructor(c);
			SecureExternalizableWithoutInnerSizeControl res=(SecureExternalizableWithoutInnerSizeControl)cons.newInstance();
			res.readExternal(objectInput);

			return objectInput.getObjectResolver().resolveObject(res);
		}
		catch(InvocationTargetException | NoSuchMethodException | IllegalAccessException | InstantiationException e)
		{
			throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN, e);
		}

	}
	static SecureExternalizableWithoutInnerSizeControl readExternalizable(final SecuredObjectInputStream objectInput, boolean supportNull) throws IOException, ClassNotFoundException
	{
		if (!supportNull || objectInput.readBoolean())
		{

			Class<?> c=readClass(objectInput, false, SecureExternalizableWithoutInnerSizeControl.class);
			return readExternalizable(objectInput, c);
		}
		else
			return null;

	}

	static void writeObject(final SecuredObjectOutputStream oos, Object o, int sizeMax, boolean supportNull) throws IOException
	{
		writeObject(oos, o, sizeMax, supportNull, true);
	}
	@SuppressWarnings("BooleanMethodIsAlwaysInverted")
	public static boolean isSerializable(Object o)
	{
		if (o==null)
			return true;
		Class<?> clazz=o.getClass();
		if (SecureExternalizableWithoutInnerSizeControl.class.isAssignableFrom(clazz))
			return true;
		for (Class<?> c : collectionsClasses) {
			if (c.equals(clazz)) {
				for (Object ol : (Collection<?>)o)
				{
					if (!isSerializable(ol))
						return false;
				}
				return true;
			}
		}
		for (Class<?> c : mapClasses) {
			if (c.equals(clazz)) {
				for (Map.Entry<?, ?> e : ((Map<?, ?>)o).entrySet())
				{
					if (!isSerializable(e.getKey()))
						return false;
					if (!isSerializable(e.getValue()))
						return false;
				}
				return true;
			}
		}
		if (o instanceof Object[])
		{
			for (Object ot : (Object[])o) {
				if (!isSerializable(ot))
					return false;
			}
			return true;
		}
		return FilePermissions.class==clazz
				|| Enum.class.isAssignableFrom(clazz)
				|| String.class==clazz
				|| byte[].class.isAssignableFrom(clazz)
				|| byte[][].class.isAssignableFrom(clazz)
				|| SecureExternalizable[].class.isAssignableFrom(clazz)
				|| InetSocketAddress.class==clazz
				|| InetAddress.class==clazz
				|| Number.class.isAssignableFrom(clazz)
				|| BigInteger.class==clazz
				|| BigDecimal.class==clazz;

	}
	private static int getObjectCodeSizeBytes()
	{
		return enumsEndIndex>254?2:1;
	}
	private static void writeObjectCode(final SecuredObjectOutputStream oos, int code) throws IOException {
		if (code>MAX_UNSIGNED_SHORT_VALUE || code<0)
			throw new IllegalAccessError();
		if (enumsEndIndex>254)
			oos.writeUnsignedShort(code);
		else
			oos.writeUnsignedByte(code);
	}
	private static int readObjectCode(final SecuredObjectInputStream ois) throws IOException {
		if (enumsEndIndex>254)
		{
			return ois.readUnsignedShort();
		}
		else
		{
			return ois.readUnsignedByte();
		}
	}
	private static int getSizeCoderSize(int maxSize)  {
		if (maxSize<0)
			throw new IllegalArgumentException();
		if (maxSize>254)
		{
			if (maxSize>MAX_UNSIGNED_SHORT_VALUE) {
				if (maxSize>MAX_UNSIGNED_SHORT_INT_VALUE)
					return 4;
				else
					return 3;
			}
			else
				return 2;
		}
		else
			return 0;
	}
	private static final int MAX_UNSIGNED_SHORT_INT_VALUE=1<<24-2;
	private static final int MAX_UNSIGNED_SHORT_VALUE=1<<16-2;

	private static void writeSize(final SecuredObjectOutputStream oos, boolean nullObject, int size, int maxSize) throws IOException {
		if (maxSize<0)
			throw new IllegalArgumentException();
		if (size<0)
			throw new IllegalArgumentException();
		if (size>maxSize)
			throw new IllegalArgumentException();

		if (maxSize>254) {

			if (maxSize > MAX_UNSIGNED_SHORT_VALUE) {
				if (maxSize>MAX_UNSIGNED_SHORT_INT_VALUE) {
					if (nullObject)
						oos.writeInt(-1);
					else
						oos.writeInt(size);
				}
				else {
					if (nullObject)
						oos.writeUnsignedShortInt(MAX_UNSIGNED_SHORT_INT_VALUE+1);
					else
						oos.writeUnsignedShortInt(size);
				}
			}
			else{
				if (nullObject)
					oos.writeUnsignedShort(MAX_UNSIGNED_SHORT_VALUE+1);
				else
					oos.writeUnsignedShort(size);
			}
		}
		else{
			if (nullObject)
				oos.writeUnsignedByte(255);
			else
				oos.writeUnsignedByte(size);
		}
	}
	private static int readSize(final SecuredObjectInputStream ois, int maxSize) throws IOException {
		if (maxSize<0)
			throw new IllegalArgumentException();
		int res;
		if (maxSize>254)
		{
			if (maxSize>MAX_UNSIGNED_SHORT_VALUE)
			{
				if (maxSize>MAX_UNSIGNED_SHORT_INT_VALUE)
				{
					res=ois.readInt();
				}
				else {
					res = ois.readUnsignedShortInt();
					if (res==MAX_UNSIGNED_SHORT_INT_VALUE+1)
						res=-1;
				}
			}
			else {
				res = ois.readUnsignedShort();
				if (res==MAX_UNSIGNED_SHORT_VALUE+1)
					res=-1;
			}
		}
		else
		{
			res=ois.readUnsignedByte();
			if (res==255)
				res=-1;
		}
		if (res<-1 || res>maxSize)
			throw new MessageExternalizationException(Integrity.FAIL);
		return res;
	}
	private static void writeObject(final SecuredObjectOutputStream oos, Object o, int sizeMax, boolean supportNull, boolean OOSreplaceObject) throws IOException
	{
		Short id;

		if (o==null)
		{
			if (!supportNull)
				throw new IOException();

			writeObjectCode(oos, 0);
		}
		else {
			Class<?> clazz=o.getClass();
			if (o instanceof Collection) {
				writeObjectCode(oos, 28);
				writeCollection(oos, (Collection<?>) o, sizeMax, false, true);
			} else if (o instanceof Map) {
				writeObjectCode(oos, 13);
				writeMap(oos, (Map<?, ?>) o, sizeMax, false, true, true);
			} else if (clazz == FilePermissions.class) {
				writeObjectCode(oos, 27);
				((FilePermissions) o).writeExternal(oos);
			} else if (o instanceof SecureExternalizableWithoutInnerSizeControl && (id = identifiersPerClasses.get(o.getClass())) != null) {
				if (OOSreplaceObject) {
					try {
						o = oos.getObjectResolver().replaceObject((SecureExternalizableWithoutInnerSizeControl) o);
						if (o == null)
							throw new IOException();
						writeObject(oos, o, sizeMax, false, false);
						return;
					} catch (Exception e2) {
						throw new IOException(e2);
					}
				}

				writeObjectCode(oos, id);
				writeExternalizable(oos, (SecureExternalizableWithoutInnerSizeControl) o);
			} else if (o instanceof Enum && (id = identifiersPerEnums.get(o.getClass())) != null) {
				writeObjectCode(oos, id);
				oos.writeInt(((Enum<?>) o).ordinal());
			} else if (o instanceof SecureExternalizableWithoutInnerSizeControl) {
				writeObjectCode(oos, 1);
				writeExternalizable(oos, (SecureExternalizableWithoutInnerSizeControl) o, false);
			} else if (clazz == String.class) {
				writeObjectCode(oos, 2);
				writeString(oos, (String) o, sizeMax, false);
			} else if (clazz == byte[].class) {
				writeObjectCode(oos, 3);
				writeBytes(oos, (byte[]) o, sizeMax, false);
			} else if (clazz == byte[][].class) {
				writeObjectCode(oos, 4);
				writeBytes2D(oos, (byte[][]) o, sizeMax, sizeMax, false, false);
			} else if (o instanceof SecureExternalizable[]) {
				writeObjectCode(oos, 5);
				writeExternalizables(oos, (SecureExternalizable[]) o, sizeMax, false);
			} else if (o instanceof Object[]) {
				writeObjectCode(oos, 6);
				writeObjects(oos, (Object[]) o, sizeMax, false);
			} else if (clazz == InetSocketAddress.class) {
				writeObjectCode(oos, 7);
				writeInetSocketAddress(oos, (InetSocketAddress) o, false);
			} else if (clazz == Inet6Address.class || clazz == Inet4Address.class) {
				writeObjectCode(oos, 8);
				writeInetAddress(oos, (InetAddress) o, false);
			} else if (o instanceof AbstractDecentralizedID) {
				writeObjectCode(oos, 9);
				writeDecentralizedID(oos, (AbstractDecentralizedID) o, false);
			} else if (o instanceof AbstractKey) {
				writeObjectCode(oos, 10);
				writeKey(oos, (AbstractKey) o, false);
			} else if (o instanceof AbstractKeyPair) {
				writeObjectCode(oos, 11);
				writeKeyPair(oos, (AbstractKeyPair<?, ?>) o, false);
			} else if (o instanceof Enum<?>) {
				writeObjectCode(oos, 12);
				writeEnum(oos, (Enum<?>) o, false);
			} else if (o instanceof Class) {
				writeObjectCode(oos, 14);
				writeClass(oos, (Class<?>) o, false, Object.class);
			} else if (clazz == Date.class) {
				writeObjectCode(oos, 15);
				writeDate(oos, (Date) o, false);
			} else if (o instanceof HybridKeyAgreementType) {
				writeObjectCode(oos, 16);
				writeHybridKeyAgreementType(oos, (HybridKeyAgreementType) o, false);
			} else if (o instanceof HybridASymmetricAuthenticatedSignatureType) {
				writeObjectCode(oos, 17);
				writeHybridASymmetricAuthenticatedSignatureType(oos, (HybridASymmetricAuthenticatedSignatureType) o, false);
			} else if (o instanceof HybridASymmetricEncryptionType) {
				writeObjectCode(oos, 18);
				writeHybridASymmetricEncryptionType(oos, (HybridASymmetricEncryptionType) o, false);
			} else if (clazz == Long.class) {
				writeObjectCode(oos, 19);
				oos.writeLong(((Long) o));
			} else if (clazz == Byte.class) {
				writeObjectCode(oos, 20);
				oos.write(((Byte) o));
			} else if (clazz == Short.class) {
				writeObjectCode(oos, 21);
				oos.writeShort(((Short) o));
			} else if (clazz == Integer.class) {
				writeObjectCode(oos, 22);
				oos.writeInt(((Integer) o));
			} else if (clazz == Character.class) {
				writeObjectCode(oos, 23);
				oos.writeChar(((Character) o));
			} else if (clazz==Boolean.class) {
				writeObjectCode(oos, 24);
				oos.writeBoolean(((Boolean) o));
			} else if (clazz==Float.class) {
				writeObjectCode(oos, 25);
				oos.writeFloat(((Float) o));
			} else if (clazz==Double.class) {
				writeObjectCode(oos, 26);
				oos.writeDouble(((Double) o));
			} else if (clazz==BigDecimal.class) {
				writeObjectCode(oos, 29);
				writeBigDecimal(oos, (BigDecimal)o, false);
			} else if (clazz==BigInteger.class) {
				writeObjectCode(oos, 30);
				writeBigInteger(oos, (BigInteger)o, false);
			} else {
				throw new IOException(""+clazz);

			}
		}
	}

	static Object readObject(final SecuredObjectInputStream ois, int sizeMax, boolean supportNull) throws IOException, ClassNotFoundException
	{
		int type=readObjectCode(ois);
		if (type>=classesStartIndex)
		{
			if (type<=classesEndIndex)
			{
				Class<?> c=classes.get(type-classesStartIndex);

				return readExternalizable(ois, c);
			}
			else if (type<=enumsEndIndex)
			{
				int ordinal=ois.readInt();
				Class<? extends Enum<?>> c=enums.get(type-enumsStartIndex);
				for (Enum<?> e : c.getEnumConstants())
				{
					if (e.ordinal()==ordinal)
						return e;
				}
				throw new MessageExternalizationException(Integrity.FAIL);
			}
			else
				throw new MessageExternalizationException(Integrity.FAIL);
		}
		else {
			switch (type) {
				case 0:
					if (!supportNull)
						throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN);
					return null;
				case 1:
					return readExternalizable(ois, false);
				case 2:
					return readString(ois, sizeMax, false);
				case 3:
					return readBytes(ois, false, null, 0, sizeMax);
				case 4:
					return readBytes2D(ois, sizeMax, sizeMax, false, false);
				case 5:
					return readExternalizables(ois, sizeMax, false);
				case 6:
					return readObjects(ois, sizeMax, false);
				case 7:
					return readInetSocketAddress(ois, false);
				case 8:
					return readInetAddress(ois, false);
				case 9:
					return readDecentralizedID(ois, false);
				case 10:
					return readKey(ois, false);
				case 11:
					return readKeyPair(ois, false);
				case 12:
					return readEnum(ois, false);
				case 13:
					return readMap(ois, sizeMax, false, true, true);
				case 14:
					return readClass(ois, false, Object.class);
				case 15:
					return readDate(ois, false);
				case 16:
					return readHybridKeyAgreementType(ois, false);
				case 17:
					return readHybridASymmetricAuthenticatedSignatureType(ois, false);
				case 18:
					return readHybridASymmetricEncryptionType(ois, false);
				case 19:
					return ois.readLong();
				case 20:
					return ois.readByte();
				case 21:
					return ois.readShort();
				case 22:
					return ois.readInt();
				case 23:
					return ois.readChar();
				case 24:
					return ois.readBoolean();
				case 25:
					return ois.readFloat();
				case 26:
					return ois.readDouble();
				case 27: {
					FilePermissions fp=FilePermissions.from();
					fp.readExternal(ois);
					return fp;
				}
				case 28: {
					return readCollection(ois, sizeMax, false, true);
				}
				case 29: {
					return readBigDecimal(ois, false);
				}
				case 30: {
					return readBigInteger(ois, false);
				}

		/*case Byte.MAX_VALUE:
			return ois.readObject();*/
				default:
					throw new MessageExternalizationException(Integrity.FAIL);
			}
		}
		
	}

	private static final short lastObjectCode=30;
	private static final short classesStartIndex=lastObjectCode+1;
	private static short classesEndIndex=0;
	private static short enumsStartIndex=0;
	private static short enumsEndIndex=0;
	private static final ArrayList<Class<? extends SecureExternalizableWithoutInnerSizeControl>> classes= new ArrayList<>();
	private static final Map<Class<? extends SecureExternalizableWithoutInnerSizeControl>, Short> identifiersPerClasses=new HashMap<>();
	private static final Map<Class<? extends Enum<?>>, Short> identifiersPerEnums=new HashMap<>();
	private static final ArrayList<Class<? extends Enum<?>>> enums=new ArrayList<>();
	static {
		setPredefinedClasses( new ArrayList<>(
				Arrays.asList((Class<? extends SecureExternalizableWithoutInnerSizeControl>) FilePermissions.class,
						SubStreamParameter.class,
						SubStreamParameters.class,
						FragmentedStreamParameters.class)),
				new ArrayList<>(Arrays.asList(
						MessageDigestType.class,
						SecureRandomType.class,
						SymmetricEncryptionType.class,
						SymmetricAuthenticatedSignatureType.class,
						ASymmetricEncryptionType.class,
						ASymmetricAuthenticatedSignatureType.class,
						KeyAgreementType.class,
						PasswordHashType.class,
						SymmetricKeyWrapperType.class,
						ASymmetricKeyWrapperType.class,
						ASymmetricLoginAgreementType.class,
						CodeProvider.class,
						EllipticCurveDiffieHellmanType.class,
						P2PLoginAgreementType.class,
						PasswordBasedKeyGenerationType.class,
						OS.class,
						OSVersion.class)));
	}

	public static void addPredefinedClasses(List<Class<? extends SecureExternalizableWithoutInnerSizeControl>> cls, List<Class<? extends Enum<?>>> enms)
	{
		synchronized (SerializationTools.class) {
			if (classes.size() + enums.size() + cls.size() + enms.size() + classesStartIndex > MAX_UNSIGNED_SHORT_VALUE)
				throw new IllegalArgumentException("Too much given predefined classes");
			if (classes.size()>0) {
				cls = new ArrayList<>(cls);
				cls.removeIf(classes::contains);
			}
			if (enums.size()>0) {
				enms = new ArrayList<>(enms);
				enms.removeIf(enums::contains);
			}

			classes.addAll(cls);
			enums.addAll(enms);

			short currentID = lastObjectCode;
			for (Class<?> c : classes)
				assert !Modifier.isAbstract(c.getModifiers()) : "" + c;
			assert currentID + classes.size() < MAX_UNSIGNED_SHORT_VALUE;
			for (Class<? extends SecureExternalizableWithoutInnerSizeControl> c : classes) {
				short id = ++currentID;
				identifiersPerClasses.put(c, id);
			}
			classesEndIndex = currentID;


			assert currentID + enums.size() < MAX_UNSIGNED_SHORT_VALUE;
			enumsStartIndex = (short)(currentID + 1);
			for (Class<? extends Enum<?>> c : enums) {
				short id = (++currentID);
				identifiersPerEnums.put(c, id);
			}
			enumsEndIndex = currentID;
		}
	}

	public static void setPredefinedClasses(List<Class<? extends SecureExternalizableWithoutInnerSizeControl>> cls, List<Class<? extends Enum<?>>> enms)
	{
		synchronized (SerializationTools.class) {
			classes.clear();
			enums.clear();
			addPredefinedClasses(cls, enms);
		}
	}

	public static List<Class<? extends SecureExternalizableWithoutInnerSizeControl>> getPredefinedClasses() {
		return Collections.unmodifiableList(classes);
	}

	public static List<Class<? extends Enum<?>>> getPredefinedEnums() {
		return Collections.unmodifiableList(enums);
	}

	public static int getInternalSize(Number key)
	{
		if (key==null)
			return 1;
		return getInternalSize(key, 0);
	}

	public static int getInternalSize(IKey key)
	{
		if (key==null)
			return 1;
		return getInternalSize(key, 0);
	}

	public static int getInternalSize(AbstractKeyPair<?, ?> keyPair)
	{
		if (keyPair==null)
			return 1;
		return getInternalSize(keyPair, 0);
	}
	public static int getInternalSize(InetAddress inetAddress)
	{
		if (inetAddress==null)
			return 1;
		return getInternalSize(inetAddress, 0);
	}
	public static int getInternalSize(HybridKeyAgreementType v)
	{
		if (v==null)
			return 1;
		return getInternalSize(v, 0);
	}
	public static int getInternalSize(HybridASymmetricAuthenticatedSignatureType v)
	{
		if (v==null)
			return 1;
		return getInternalSize(v, 0);
	}
	public static int getInternalSize(HybridASymmetricEncryptionType v)
	{
		if (v==null)
			return 1;
		return getInternalSize(v, 0);
	}
	public static int getInternalSize(InetSocketAddress inetSocketAddress)
	{
		if (inetSocketAddress==null)
			return 1;
		return getInternalSize(inetSocketAddress, 0);
	}
	public static int getInternalSize(Class<?> clazz)
	{
		return getInternalSize( clazz, MAX_CLASS_LENGTH);
	}
	public static int getInternalSize(BigInteger bigInteger)
	{
		return getInternalSize( bigInteger, 0);
	}
	public static int getInternalSize(BigDecimal bigDecimal)
	{
		return getInternalSize( bigDecimal, 0);
	}
	public static int getInternalSize(AbstractDecentralizedID abstractDecentralizedID)
	{
		if (abstractDecentralizedID==null)
			return 1;
		return getInternalSize(abstractDecentralizedID, 0);
	}
	public static int getInternalSize(SecureExternalizable secureExternalizable)
	{
		if (secureExternalizable==null)
			return 1;

		return getInternalSize(secureExternalizable, 0);
	}
	public static int getInternalSize(Enum<?> e)
	{
		if (e==null)
			return 1;
		return getInternalSize(e, 0);
	}
	public static int getInternalSize(byte[] array, int maxSizeInBytes)
	{
		if (array==null)
			return getSizeCoderSize(maxSizeInBytes);
		return getInternalSize((Object)array, maxSizeInBytes);
	}
	public static int getInternalSize(Object[] array, int maxSizeInBytes)
	{
		if (array==null)
			return getSizeCoderSize(maxSizeInBytes);
		return getInternalSize((Object)array, maxSizeInBytes);
	}
	public static int getInternalSize(String text, int maxSizeInBytes)
	{
		if (text==null)
			return getSizeCoderSize(maxSizeInBytes);
		return getInternalSize((Object)text, maxSizeInBytes);
	}
	public static int getInternalSize(Collection<Object> array, int maxSizeInBytes)
	{
		if (array==null)
			return getSizeCoderSize(maxSizeInBytes);
		return getInternalSize((Object)array, maxSizeInBytes);
	}
	public static int getInternalSize(byte[][] array, int maxSizeInBytes1, int maxSizeInBytes2)
	{
		int res=getSizeCoderSize(maxSizeInBytes1);
		for (byte[] b : array)
			res+=getSizeCoderSize(maxSizeInBytes2)+(b==null?0:b.length);
		return res;
	}


	public static int getInternalSize(Object o, int sizeMax)
	{
		if (o ==null)
			return getObjectCodeSizeBytes();
		Class<?> clazz=o.getClass();
		if (clazz==String.class)
		{
			return getObjectCodeSizeBytes()+((String)o).length()*2+getSizeCoderSize(sizeMax);
		}
		else if (o instanceof Collection)
		{
			Collection<?> c=(Collection<?>)o;
			int res=getObjectCodeSizeBytes()+getSizeCoderSize(sizeMax);
			sizeMax-=c.size();
			for (Object oc : c)
				res+=getInternalSize(oc, sizeMax);

			return res;
		}
		else if (o instanceof Map)
		{
			Map<?, ?> m=(Map<?, ?>)o;
			int res=getObjectCodeSizeBytes()+getSizeCoderSize(sizeMax);
			sizeMax-=m.size();
			for (Map.Entry<?, ?> e: m.entrySet())
				res+=getInternalSize(e.getKey(), sizeMax)+getInternalSize(e.getValue(), sizeMax);

			return res;
		}
		else if (o instanceof byte[])
		{
			return getObjectCodeSizeBytes()+((byte[])o).length+getSizeCoderSize(sizeMax);
		}
		else if (o instanceof byte[][])
		{
			byte[][] tab = ((byte[][]) o);
			int res=getObjectCodeSizeBytes()+getSizeCoderSize(sizeMax);
			for (byte[] b : tab) {
				res += getObjectCodeSizeBytes()+getSizeCoderSize(sizeMax) + (b == null ? 0 : b.length);
			}
			return res;
		}
		else if (o instanceof SecureExternalizable)
		{
			int res=getObjectCodeSizeBytes()+((SecureExternalizable)o).getInternalSerializedSize();
			if (!classes.contains(o.getClass()))
				res+=getInternalSize(o.getClass().getName(), MAX_CLASS_LENGTH);
			return res;
		}
		else if (o instanceof SecureExternalizable[])
		{
			int size=getObjectCodeSizeBytes()+getSizeCoderSize(sizeMax);
			for (SecureExternalizable s : (SecureExternalizable[])o) {
				size+=1;
				if (s!=null) {
					if (!classes.contains(o.getClass()))
						size += getInternalSize(s.getClass().getName(), MAX_CLASS_LENGTH) ;
					size += s.getInternalSerializedSize();
				}
			}
			return size;
		}
		else if (o instanceof Object[])
		{
			Object[] tab = (Object[]) o;
			int size=getObjectCodeSizeBytes()+getSizeCoderSize(sizeMax);
			for (Object so : tab)
			{
				size+=getInternalSize(so, sizeMax-size);
			}
			return size;
		}
		else if (clazz==InetAddress.class)
		{
			return getObjectCodeSizeBytes()+((InetAddress)o).getAddress().length+2;
		}
		else if (clazz==InetSocketAddress.class)
		{
			return getObjectCodeSizeBytes()+((InetSocketAddress)o).getAddress().getAddress().length+6;
		}
		else if (o instanceof DecentralizedValue)
		{
			return getObjectCodeSizeBytes()+4+((DecentralizedValue) o).encode().length;
		}
		else if (o instanceof Enum<?>)
		{
			int res=getObjectCodeSizeBytes()+4;
			if (enums.contains(clazz))
				res+=2;
			else
				res+=getInternalSize(o.getClass().getName(), MAX_CLASS_LENGTH);
			return res;
		}
		else if (clazz==Class.class){
			int res=getObjectCodeSizeBytes();
			if (enums.contains(clazz))
				res+=2;
			else
				res+=SerializationTools.getInternalSize(clazz.getName(), MAX_CLASS_LENGTH);
			return res;
		}
		else if (clazz==Date.class){
			return getObjectCodeSizeBytes()+8;
		}
		else if (o instanceof HybridKeyAgreementType)
		{
			return getObjectCodeSizeBytes()+16;
		}
		else if (o instanceof HybridASymmetricAuthenticatedSignatureType)
		{
			return getObjectCodeSizeBytes()+16;
		}
		else if (o instanceof HybridASymmetricEncryptionType)
		{
			return getObjectCodeSizeBytes()+16;
		}
		else if (clazz==Long.class){
			return getObjectCodeSizeBytes()+8;
		}
		else if (clazz==Integer.class){
			return getObjectCodeSizeBytes()+4;
		}
		else if (clazz==Byte.class){
			return getObjectCodeSizeBytes()+1;
		}
		else if (clazz==Short.class){
			return getObjectCodeSizeBytes()+2;
		}
		else if (clazz==Float.class){
			return getObjectCodeSizeBytes()+4;
		}
		else if (clazz==Double.class){
			return getObjectCodeSizeBytes()+8;
		}
		else if (clazz==Character.class){
			return getObjectCodeSizeBytes()+2;
		}
		else if (clazz==Boolean.class){
			return getObjectCodeSizeBytes()+1;
		}
		else if (clazz==BigInteger.class){
			BigInteger b=(BigInteger)o;
			return getObjectCodeSizeBytes()+getInternalSize(b.toByteArray().length, MAX_BIG_INTEGER_SIZE);
		}
		else if (clazz==BigDecimal.class){
			BigDecimal b=(BigDecimal)o;
			return getObjectCodeSizeBytes()+4+getInternalSize(b.unscaledValue().toByteArray().length, MAX_BIG_INTEGER_SIZE);
		}
		else
			throw new IllegalArgumentException();
	}

	public static class ObjectResolver
	{
		public Class<?> resolveClass(String clazz) throws MessageExternalizationException
		{
			return resolveClass(clazz, true);
		}
		public Class<?> resolveClass(String clazz, boolean initialize) throws MessageExternalizationException
		{
			try
			{
				return Class.forName(clazz, initialize, ReflectionTools.getClassLoader());
			}
			catch(Exception e)
			{
				throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN, new ClassNotFoundException(clazz));
			}

		}

		@SuppressWarnings("RedundantThrows")
		public SecureExternalizableWithoutInnerSizeControl replaceObject(SecureExternalizableWithoutInnerSizeControl o) throws IOException
		{
			return o;
		}

		@SuppressWarnings("RedundantThrows")
		public SecureExternalizableWithoutInnerSizeControl resolveObject(SecureExternalizableWithoutInnerSizeControl o) throws IOException
		{
			return o;
		}
	}

}

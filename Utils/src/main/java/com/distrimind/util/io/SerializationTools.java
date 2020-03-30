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


import com.distrimind.util.AbstractDecentralizedID;
import com.distrimind.util.OS;
import com.distrimind.util.OSVersion;
import com.distrimind.util.ReflectionTools;
import com.distrimind.util.crypto.*;
import com.distrimind.util.harddrive.FilePermissions;
import com.distrimind.util.sizeof.ObjectSizer;

import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Modifier;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.*;



/**
 * 
 * @author Jason Mahdjoub
 * @since Utils 4.5.0
 * @version 2.1
 * 
 */

public class SerializationTools {
	private static final int MAX_CHAR_BUFFER_SIZE=Short.MAX_VALUE*5;
	
	static void writeString(final SecuredObjectOutputStream oos, String s, int sizeMax, boolean supportNull) throws IOException
	{
		if (sizeMax<0)
			throw new IllegalArgumentException();

		if (s==null)
		{
			if (!supportNull)
				throw new IOException();
			if (sizeMax>Short.MAX_VALUE)
				oos.writeInt(-1);
			else
				oos.writeShort(-1);
			return;
			
		}
			
		if (s.length()>sizeMax)
			throw new IOException();
		if (sizeMax>Short.MAX_VALUE)
			oos.writeInt(s.length());
		else
			oos.writeShort(s.length());
		oos.writeChars(s);
	}
	private static final Object stringLocker=new Object();
	
	private static char[] chars=null;

	static String readString(final SecuredObjectInputStream ois, int sizeMax, boolean supportNull) throws IOException
	{
		if (sizeMax<0)
			throw new IllegalArgumentException();
		int size;
		if (sizeMax>Short.MAX_VALUE)
			size=ois.readInt();
		else
			size=ois.readShort();
		if (size==-1)
		{
			if (!supportNull)
				throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN);
			return null;
		}
		if (size<0 || size>sizeMax)
			throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN, "size="+size+", sizeMax="+sizeMax);
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
		if (sizeMax<0)
			throw new IllegalArgumentException();

		if (tab==null)
		{
			if (!supportNull)
				throw new IOException();
			if (sizeMax>Short.MAX_VALUE)
				oos.writeInt(-1);
			else
				oos.writeShort(-1);
			return;
			
		}
		if (size>sizeMax)
			throw new IOException();
		if (sizeMax>Short.MAX_VALUE)
			oos.writeInt(size);
		else
			oos.writeShort(size);
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
		if (sizeMax1<0)
			throw new IllegalArgumentException();
		if (sizeMax2<0)
			throw new IllegalArgumentException();

		if (tab==null)
		{
			if (!supportNull1)
				throw new IOException();
			if (sizeMax1>Short.MAX_VALUE)
				oos.writeInt(-1);
			else
				oos.writeShort(-1);
			return;
			
		}
		if (size>sizeMax1)
			throw new IOException();
		if (sizeMax1>Short.MAX_VALUE)
			oos.writeInt(size);
		else
			oos.writeShort(size);
		for (int i=off;i<size;i++) {
			byte[] b=tab[i];
			SerializationTools.writeBytes(oos, b, 0, b==null?0:b.length, sizeMax2, supportNull2);
		}
	}
	@SuppressWarnings("SameParameterValue")
	static byte[][] readBytes2D(final SecuredObjectInputStream ois, int sizeMax1, int sizeMax2, boolean supportNull1, boolean supportNull2) throws IOException
	{
		if (sizeMax1<0)
			throw new IllegalArgumentException();
		if (sizeMax2<0)
			throw new IllegalArgumentException();


		int size;
		if (sizeMax1>Short.MAX_VALUE)
			size=ois.readInt();
		else
			size=ois.readShort();
		if (size==-1)
		{
			if (!supportNull1)
				throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN);
			return null;
		}
		if (size<0 || size>sizeMax1)
			throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN);
		
		byte [][]tab=new byte[size][];
		for (int i=0;i<size;i++)
			tab[i]=readBytes(ois, supportNull2, null, 0, sizeMax2);
		
		
		return tab;
		
	}
	@SuppressWarnings("SameParameterValue")
	static byte[] readBytes(final SecuredObjectInputStream ois, boolean supportNull, byte[] tab, int off, int sizeMax) throws IOException
	{
		if (sizeMax<0)
			throw new IllegalArgumentException();

		int size;
		if (sizeMax>Short.MAX_VALUE)
			size=ois.readInt();
		else
			size=ois.readShort();
		if (size==-1)
		{
			if (!supportNull)
				throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN);
			return null;
		}
		if (size<0 || size>sizeMax)
			throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN);
		if (tab==null) {
			tab = new byte[size];
			off = 0;
		}


		ois.readFully(tab, off, size);
		
		return tab;
		
	}
	
	public static final int MAX_KEY_SIZE=Short.MAX_VALUE;
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

		writeBytes(oos, key.encode(), MAX_KEY_SIZE, false);
	}

	@SuppressWarnings("SameParameterValue")
	static AbstractKey readKey(final SecuredObjectInputStream in, boolean supportNull) throws IOException
	{
		if (!supportNull || in.readBoolean())
		{
			byte[] k=readBytes(in, false, null, 0, MAX_KEY_SIZE);
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

		
		writeBytes(oos, keyPair.encode(), MAX_KEY_SIZE*2, false);
	}

	@SuppressWarnings("SameParameterValue")
	static AbstractKeyPair<?, ?> readKeyPair(final SecuredObjectInputStream in, boolean supportNull) throws IOException
	{
		if (!supportNull || in.readBoolean())
		{
			byte[] k=readBytes(in, false, null, 0, MAX_KEY_SIZE*2);
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
		if (sizeMax<0)
			throw new IllegalArgumentException();

		if (tab==null)
		{
			if (!supportNull)
				throw new IOException();
			if (sizeMax>Short.MAX_VALUE)
				oos.writeInt(-1);
			else
				oos.writeShort(-1);
			return;

		}
		if (tab.length>sizeMax)
			throw new IOException();
		if (sizeMax>Short.MAX_VALUE)
			oos.writeInt(tab.length);
		else
			oos.writeShort(tab.length);
		sizeMax-=tab.length;
		for (Object o : tab)
		{
			writeObject(oos, o, sizeMax, true);
		}
	}

	@SuppressWarnings("SameParameterValue")
	static Object[] readObjects(final SecuredObjectInputStream ois, int sizeMax, boolean supportNull) throws IOException, ClassNotFoundException
	{
		if (sizeMax<0)
			throw new IllegalArgumentException();

		int size;
		if (sizeMax>Short.MAX_VALUE)
			size=ois.readInt();
		else
			size=ois.readShort();
		if (size==-1)
		{
			if (!supportNull)
				throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN);
			return null;
		}
		if (size<0 || size>sizeMax)
			throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN);

		Object []tab=new Object[size];
		sizeMax-=tab.length;
		for (int i=0;i<size;i++)
		{
			tab[i]=readObject(ois, sizeMax, true);
		}

		return tab;

	}
	@SuppressWarnings("SameParameterValue")
	static ArrayList<Object> readListObjects(final SecuredObjectInputStream ois, int sizeMax, boolean supportNull) throws IOException, ClassNotFoundException
	{
		if (sizeMax<0)
			throw new IllegalArgumentException();

		int size;
		if (sizeMax>Short.MAX_VALUE)
			size=ois.readInt();
		else
			size=ois.readShort();
		if (size==-1)
		{
			if (!supportNull)
				throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN);
			return null;
		}
		if (size<0 || size>sizeMax)
			throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN);

		ArrayList<Object> tab=new ArrayList<>(size);
		sizeMax-=size;
		for (int i=0;i<size;i++)
		{
			tab.add(readObject(ois, sizeMax, true));
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
		if (supportNull)
			oos.writeBoolean(e!=null);
		if (e==null)
		{
			if (!supportNull)
				throw new IOException();

			return;

		}

		SerializationTools.writeString(oos, e.getClass().getName(), MAX_CLASS_LENGTH, false);
		SerializationTools.writeString(oos, e.name(), 1000, false);
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
		SerializationTools.writeString(oos, e.getNonPQCKeyAgreementType().name(), 1000, false);
		SerializationTools.writeString(oos, e.getPQCKeyAgreementType().name(), 1000, false);
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
		SerializationTools.writeString(oos, e.getNonPQCASymmetricEncryptionType().name(), 1000, false);
		SerializationTools.writeString(oos, e.getPQCASymmetricEncryptionType().name(), 1000, false);
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
		SerializationTools.writeString(oos, e.getNonPQCASymmetricAuthenticatedSignatureType().name(), 1000, false);
		SerializationTools.writeString(oos, e.getPQCASymmetricAuthenticatedSignatureType().name(), 1000, false);
	}
	public final static int MAX_CLASS_LENGTH=2048;


	@SuppressWarnings("SameParameterValue")
	static Enum<?> readEnum(final SecuredObjectInputStream ois, boolean supportNull) throws IOException, ClassNotFoundException
	{
		if (!supportNull || ois.readBoolean())
		{
			String clazz=SerializationTools.readString(ois, MAX_CLASS_LENGTH, false);
			String value=SerializationTools.readString(ois, 1000, false);
			@SuppressWarnings("rawtypes")
			Class c=Class.forName(clazz, false, ReflectionTools.getClassLoader());
			if (!c.isEnum())
				throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN);
			try
			{
				if (value==null)
					throw new MessageExternalizationException(Integrity.FAIL);

				return Enum.valueOf(c, value);
			}
			catch(ClassCastException e)
			{
				throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN);
			}

		}
		else
			return null;

	}
	static HybridKeyAgreementType readHybridKeyAgreementType(final SecuredObjectInputStream ois, @SuppressWarnings("SameParameterValue") boolean supportNull) throws IOException
	{
		if (!supportNull || ois.readBoolean())
		{
			KeyAgreementType ka=KeyAgreementType.valueOf(SerializationTools.readString(ois, 1000, false));
			KeyAgreementType pqcka=KeyAgreementType.valueOf(SerializationTools.readString(ois, 1000, false));
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
			ASymmetricAuthenticatedSignatureType ka=ASymmetricAuthenticatedSignatureType.valueOf(SerializationTools.readString(ois, 1000, false));
			ASymmetricAuthenticatedSignatureType pqcka=ASymmetricAuthenticatedSignatureType.valueOf(SerializationTools.readString(ois, 1000, false));
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
			ASymmetricEncryptionType ka=ASymmetricEncryptionType.valueOf(SerializationTools.readString(ois, 1000, false));
			ASymmetricEncryptionType pqcka=ASymmetricEncryptionType.valueOf(SerializationTools.readString(ois, 1000, false));
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
		if (supportNull)
			objectOutput.writeBoolean(clazz!=null);
		if (clazz!=null) {
			if (!rootClass.isAssignableFrom(clazz))
				throw new IOException();
			SerializationTools.writeString(objectOutput, clazz.getName(), MAX_CLASS_LENGTH, supportNull);
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
				c=AccessController.doPrivileged(new PrivilegedAction<Constructor<?>>() {

					@Override
					public Constructor<?> run() {

						cons.setAccessible(true);
						return cons;
					}
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

		if (!supportNull || objectInput.readBoolean())
		{
			String clazz=SerializationTools.readString(objectInput, MAX_CLASS_LENGTH, false);

			boolean doubleCheck=rootClass!=Object.class;
			Class<?> c=objectInput.getObjectResolver().resolveClass(clazz, !doubleCheck);

			if (doubleCheck) {
				if (!rootClass.isAssignableFrom(c))
					throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN, "rootClass : "+rootClass+" ; class="+c);
				c = Class.forName(clazz, true, ReflectionTools.getClassLoader());
			}
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
	private static void writeObject(final SecuredObjectOutputStream oos, Object o, int sizeMax, boolean supportNull, boolean OOSreplaceObject) throws IOException
	{
		Short id;

		if (o==null)
		{
			if (!supportNull)
				throw new IOException();
			
			oos.write(0);
		}
		else if (o instanceof FilePermissions)
		{
			oos.write(27);
			((FilePermissions) o).writeExternal(oos);
		}
		else if (o instanceof SecureExternalizableWithoutInnerSizeControl && (id=identifiersPerClasses.get(o.getClass()))!=null)
		{
			if (OOSreplaceObject)
			{
				try
				{
					o=oos.getObjectResolver().replaceObject((SecureExternalizableWithoutInnerSizeControl)o);
					if (o==null)
						throw new IOException();
					writeObject(oos,o,sizeMax, false, false);
					return;
				}
				catch(Exception e2)
				{
					throw new IOException(e2);
				}
			}

			oos.write(id.byteValue());
			writeExternalizable(oos, (SecureExternalizableWithoutInnerSizeControl)o);
		}
		else
			if (o instanceof Enum && (id=identifiersPerEnums.get(o.getClass()))!=null)
		{
			oos.writeByte(id.byteValue());
			oos.writeInt(((Enum<?>)o).ordinal());
		}
		else if (o instanceof SecureExternalizableWithoutInnerSizeControl)
		{
			oos.write(1);
			writeExternalizable(oos, (SecureExternalizableWithoutInnerSizeControl) o, false);
		}
		else if (o instanceof String)
		{
			oos.write(2);
			writeString(oos, (String)o, sizeMax, false);
		}
		else if (o instanceof byte[])
		{
			oos.write(3);
			writeBytes(oos, (byte[])o, sizeMax, false);
		}
		else if (o instanceof byte[][])
		{
			oos.write(4);
			writeBytes2D(oos, (byte[][])o, sizeMax, sizeMax, false, false);
		}
		else if (o instanceof SecureExternalizable[])
		{
			oos.write(5);
			writeExternalizables(oos, (SecureExternalizable[])o, sizeMax, false);
		}
		else if (o instanceof Object[])
		{
			oos.write(6);
			writeObjects(oos, (Object[])o, sizeMax, false);
		}
		else if (o instanceof InetSocketAddress)
		{
			oos.write(7);
			writeInetSocketAddress(oos, (InetSocketAddress)o, false);
		}
		else if (o instanceof InetAddress)
		{
			oos.write(8);
			writeInetAddress(oos, (InetAddress)o, false);
		}
		else if (o instanceof AbstractDecentralizedID)
		{
			oos.write(9);
			writeDecentralizedID(oos, (AbstractDecentralizedID)o, false);
		}
		else if (o instanceof AbstractKey)
		{
			oos.write(10);
			writeKey(oos, (AbstractKey)o, false);
		}
		else if (o instanceof AbstractKeyPair)
		{
			oos.write(11);
			writeKeyPair(oos, (AbstractKeyPair<?, ?>)o, false);
		}
		else if (o instanceof Enum<?>)
		{
			oos.write(12);
			writeEnum(oos, (Enum<?>)o, false);
		}
		else if (o instanceof Collection)
		{
			oos.write(13);
			Collection<?> c=(Collection<?>)o;
			Object[] tab=new Object[c.size()];
			int i=0;
			for (Object r : c)
				tab[i++]=r;
			writeObjects(oos, tab, sizeMax, false);
		}
		else if (o instanceof Class)
		{
			oos.write(14);
			writeClass(oos, (Class<?>)o, false, Object.class);
		}
		else if (o instanceof Date)
		{
			oos.write(15);
			writeDate(oos, (Date)o, false);
		}
		else if (o instanceof HybridKeyAgreementType)
		{
			oos.write(16);
			writeHybridKeyAgreementType(oos, (HybridKeyAgreementType)o, false);
		}
		else if (o instanceof HybridASymmetricAuthenticatedSignatureType)
		{
			oos.write(17);
			writeHybridASymmetricAuthenticatedSignatureType(oos, (HybridASymmetricAuthenticatedSignatureType)o, false);
		}
		else if (o instanceof HybridASymmetricEncryptionType)
		{
			oos.write(18);
			writeHybridASymmetricEncryptionType(oos, (HybridASymmetricEncryptionType)o, false);
		}
		else if (o instanceof Long)
		{
			oos.write(19);
			oos.writeLong(((Long) o));
		}
		else if (o instanceof Byte)
		{
			oos.write(20);
			oos.write(((Byte) o));
		}
		else if (o instanceof Short)
		{
			oos.write(21);
			oos.writeShort(((Short) o));
		}
		else if (o instanceof Integer)
		{
			oos.write(22);
			oos.writeInt(((Integer) o));
		}
		else if (o instanceof Character)
		{
			oos.write(23);
			oos.writeChar(((Character) o));
		}
		else if (o instanceof Boolean)
		{
			oos.write(24);
			oos.writeBoolean(((Boolean) o));
		}
		else if (o instanceof Float)
		{
			oos.write(25);
			oos.writeFloat(((Float) o));
		}
		else if (o instanceof Double)
		{
			oos.write(26);
			oos.writeDouble(((Double) o));
		}
		else
		{
			throw new IOException();
			/*oos.write(Byte.MAX_VALUE);
			oos.writeObject(o);*/
		}
	}
	
	static Object readObject(final SecuredObjectInputStream ois, int sizeMax, boolean supportNull) throws IOException, ClassNotFoundException
	{
		short type=(short)(ois.readByte() & 0xFF);
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
					return readListObjects(ois, sizeMax, false);
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

		/*case Byte.MAX_VALUE:
			return ois.readObject();*/
				default:
					throw new MessageExternalizationException(Integrity.FAIL);
			}
		}
		
	}

	private static final byte lastObjectCode=27;
	private static final short classesStartIndex=lastObjectCode+1;
	private static short classesEndIndex=0;
	private static short enumsStartIndex=0;
	private static short enumsEndIndex=0;
	private static final ArrayList<Class<? extends SecureExternalizableWithoutInnerSizeControl>> classes=new ArrayList<Class<? extends SecureExternalizableWithoutInnerSizeControl>>(
			Collections.singletonList((Class<? extends SecureExternalizableWithoutInnerSizeControl>) FilePermissions.class));
	private static final Map<Class<? extends SecureExternalizableWithoutInnerSizeControl>, Short> identifiersPerClasses=new HashMap<>();
	private static final ArrayList<Class<? extends Enum<?>>> enums=new ArrayList<>(Arrays.asList(
			MessageDigestType.class,
			SecureRandomType.class,
			SymmetricEncryptionType.class,
			SymmetricAuthentifiedSignatureType.class,
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
			OSVersion.class));
	private static final Map<Class<? extends Enum<?>>, Short> identifiersPerEnums=new HashMap<>();
	public static void addPredefinedClasses(List<Class<? extends SecureExternalizableWithoutInnerSizeControl>> cls, List<Class<? extends Enum<?>>> enms)
	{
		synchronized (SerializationTools.class) {
			if (classes.size() + enums.size() + cls.size() + enms.size() + classesStartIndex > 254)
				throw new IllegalArgumentException("Too much given predefined classes");
			classes.addAll(cls);
			enums.addAll(enms);

			short currentID = lastObjectCode;
			for (Class<?> c : classes)
				assert !Modifier.isAbstract(c.getModifiers()) : "" + c;
			assert currentID + classes.size() < 255;
			for (Class<? extends SecureExternalizableWithoutInnerSizeControl> c : classes) {
				short id = ++currentID;
				identifiersPerClasses.put(c, id);
			}
			classesEndIndex = currentID;


			assert currentID + enums.size() < 255;
			enumsStartIndex = (byte) (currentID + 1);
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
			return maxSizeInBytes>Short.MAX_VALUE?4:2;
		return getInternalSize((Object)array, maxSizeInBytes);
	}
	public static int getInternalSize(Object[] array, int maxSizeInBytes)
	{
		if (array==null)
			return maxSizeInBytes>Short.MAX_VALUE?4:2;
		return getInternalSize((Object)array, maxSizeInBytes);
	}
	public static int getInternalSize(String text, int maxSizeInBytes)
	{
		if (text==null)
			return maxSizeInBytes>Short.MAX_VALUE?4:2;
		return getInternalSize((Object)text, maxSizeInBytes);
	}
	public static int getInternalSize(Collection<Object> array, int maxSizeInBytes)
	{
		if (array==null)
			return maxSizeInBytes>Short.MAX_VALUE?4:2;
		return getInternalSize((Object)array, maxSizeInBytes);
	}
	public static int getInternalSize(byte[][] array, int maxSizeInBytes1, int maxSizeInBytes2)
	{
		int res=maxSizeInBytes1>Short.MAX_VALUE?4:2;
		for (byte[] b : array)
			res+=(maxSizeInBytes2>Short.MAX_VALUE?4:2)+(b==null?0:b.length);
		return res;
	}


	public static int getInternalSize(Object o, int sizeMax)
	{
		if (o ==null)
			return 0;
		if (o instanceof String)
		{
			return ((String)o).length()*2+sizeMax>Short.MAX_VALUE?5:3;
		}
		else if (o instanceof byte[])
		{
			return ((byte[])o).length+sizeMax>Short.MAX_VALUE?5:3;
		}
		else if (o instanceof AbstractKey)
		{
			return 4+((AbstractKey)o).encode().length;
		}
		else if (o instanceof AbstractKeyPair)
		{
			return 4+((AbstractKeyPair<?, ?>)o).encode().length;
		}
		else if (o instanceof byte[][])
		{
			byte[][] tab = ((byte[][]) o);
			int res=sizeMax>Short.MAX_VALUE?5:3;
			for (byte[] b : tab) {
				res += sizeMax>Short.MAX_VALUE?5:3 + (b == null ? 0 : b.length);
			}
			return res;
		}
		else if (o instanceof SecureExternalizable)
		{
			return ((SecureExternalizable)o).getInternalSerializedSize()+getInternalSize(o.getClass().getName(), MAX_CLASS_LENGTH);
		}
		else if (o instanceof SecureExternalizable[])
		{
			int size=sizeMax>Short.MAX_VALUE?4:2;
			for (SecureExternalizable s : (SecureExternalizable[])o) {
				size+=s==null?0:getInternalSize(s.getClass().getName(), MAX_CLASS_LENGTH);
				size += s==null?1:s.getInternalSerializedSize();
			}
			return size;
		}
		else if (o instanceof Object[])
		{
			Object[] tab = (Object[]) o;
			int size=sizeMax>Short.MAX_VALUE?5:3;
			for (Object so : tab)
			{
				size+=getInternalSize(so, sizeMax-size);
			}
			return size;
		}
		else if (o instanceof Collection)
		{
			Collection<?> c=(Collection<?>)o;
			int size=sizeMax>Short.MAX_VALUE?5:3;

			for (Object so : c)
			{
				size+=getInternalSize(so, sizeMax-size);
			}
			return size;
		}
		else if (o instanceof InetAddress)
		{
			return ((InetAddress)o).getAddress().length+4;
		}
		else if (o instanceof InetSocketAddress)
		{
			return ((InetSocketAddress)o).getAddress().getAddress().length+8;
		}
		else if (o instanceof AbstractDecentralizedID)
		{
			return ((AbstractDecentralizedID) o).encode().length+3;
		}
		else if (o instanceof Enum<?>)
		{
			return 6+((Enum<?>)o).name().length()*2+getInternalSize(o.getClass().getName(), MAX_CLASS_LENGTH);
		}
		else if (o instanceof HybridKeyAgreementType)
		{
			return 6+((HybridKeyAgreementType)o).getNonPQCKeyAgreementType().name().length()*2+((HybridKeyAgreementType)o).getPQCKeyAgreementType().name().length()*2;
		}
		else if (o instanceof HybridASymmetricAuthenticatedSignatureType)
		{
			return 6+((HybridASymmetricAuthenticatedSignatureType)o).getNonPQCASymmetricAuthenticatedSignatureType().name().length()*2+((HybridASymmetricAuthenticatedSignatureType)o).getPQCASymmetricAuthenticatedSignatureType().name().length()*2;
		}
		else if (o instanceof HybridASymmetricEncryptionType)
		{
			return 6+((HybridASymmetricEncryptionType)o).getNonPQCASymmetricEncryptionType().name().length()*2+((HybridASymmetricEncryptionType)o).getPQCASymmetricEncryptionType().name().length()*2;
		}
		else
			return 1+ObjectSizer.sizeOf(o);
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
				Class<?> c=Class.forName(clazz, initialize, ReflectionTools.getClassLoader());
				if (c==null)
					throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN, new ClassNotFoundException(clazz));
				return c;
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

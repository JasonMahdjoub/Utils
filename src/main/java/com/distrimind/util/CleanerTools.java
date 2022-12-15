package com.distrimind.util;
/*
Copyright or © or Corp. Jason Mahdjoub (01/04/2013)

jason.mahdjoub@distri-mind.fr

This software (Object Oriented Database (OOD)) is a computer program 
whose purpose is to manage a local database with the object paradigm 
and the java language 

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

import java.lang.ref.WeakReference;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;

/**
 * @author Jason Mahdjoub
 * @version 1.0
 * @since MaDKitLanEdition 5.23.0
 */
class CleanerTools {
	private static Object JAVA_CLEANER=null;
	private static final Method m_register;
	private static final Method m_clean;
	static final Method m_create;
	static
	{
		Method mr, cl, mc;
		try {
			Class<?> cc=Class.forName("java.lang.ref.Cleaner");
			Class<?> ccl=Class.forName("java.lang.ref.Cleaner$Cleanable");
			mc=cc.getDeclaredMethod("create");
			mr=cc.getDeclaredMethod("register", Object.class, Runnable.class);
			cl=ccl.getDeclaredMethod("clean");

		} catch (ClassNotFoundException | NoSuchMethodException ignored) {
			mr=null;
			cl=null;
			mc=null;
		}
		m_register=mr;
		m_clean=cl;
		m_create=mc;
	}
	static class WR extends WeakReference<Cleanable>
	{
		private final int hashCode;
		public WR(Cleanable referent) {
			super(referent);
			hashCode=System.identityHashCode(referent);
		}

		@Override
		public boolean equals(Object obj) {
			return obj!=null && obj.getClass()==WR.class && ((WR) obj).get()==get();
		}

		@Override
		public int hashCode() {
			return hashCode;
		}
	}
	private static final Map<WR, WeakReference<Cleanable.Cleaner>> cleaners=new HashMap<>();
	static void registerCleaner(Cleanable cleanable, Cleanable.Cleaner cleaner) {
		if (cleanable==null)
			throw new NullPointerException();
		if (cleaner==null)
			throw new NullPointerException();
		synchronized (CleanerTools.class) {
			WeakReference<Cleanable.Cleaner> cleanerWR=new WeakReference<>(cleaner);
			WeakReference<Cleanable.Cleaner> previousCleaner = cleaners.putIfAbsent(cleaner.reference=new WR(cleanable), cleanerWR);
			if (previousCleaner != null) {
				Cleanable.Cleaner tmp=previousCleaner.get();
				if (tmp==cleaner)
					return;
				if (tmp==null)
					cleaners.put(cleaner.reference, cleanerWR);
				else
					tmp.setNext(cleaner);
			}

			if (m_create != null) {


				if (JAVA_CLEANER == null) {
					try {
						JAVA_CLEANER = m_create.invoke(null);
					} catch (IllegalAccessException | InvocationTargetException e) {
						e.printStackTrace();
					}
				}
				if (JAVA_CLEANER != null) {
					try {
						cleaner.setCleanable(m_register.invoke(JAVA_CLEANER, cleanable, cleaner));
					} catch (IllegalAccessException | InvocationTargetException e) {
						e.printStackTrace();
						System.exit(-1);
					}
				}
			}
		}
	}
	static void removeCleaner(Cleanable.Cleaner cleaner) {
		synchronized (CleanerTools.class)
		{
			cleaners.remove(cleaner.reference);
		}
	}
	static boolean isCleaned(Cleanable cleanable) {
		Cleanable.Cleaner c;
		synchronized (CleanerTools.class)
		{
			WeakReference<Cleanable.Cleaner> wr=cleaners.get(new WR(cleanable));
			if (wr!=null)
				c=wr.get();
			else
				c=null;
		}
		return c==null || c.isCleaned();
	}

	static void clean(Cleanable cleanable)
	{
		Cleanable.Cleaner cleaner;
		synchronized (CleanerTools.class)
		{
			WeakReference<Cleanable.Cleaner> wr=cleaners.remove(new WR(cleanable));
			if (wr!=null)
				cleaner=wr.get();
			else
				cleaner=null;

		}
		if (cleaner!=null) {

			if (CleanerTools.m_create !=null && JAVA_CLEANER!=null) {


				try {
					m_clean.invoke(cleaner.getCleanable());
				} catch (IllegalAccessException | InvocationTargetException e) {
					e.printStackTrace();
				}
			}
			else
				cleaner.runImpl(false);
		}

	}
	static void performCleanup(Cleanable cleanable)
	{
		Cleanable.Cleaner cleaner;
		synchronized (CleanerTools.class)
		{
			WeakReference<Cleanable.Cleaner> wr=cleaners.get(new WR(cleanable));
			if (wr!=null)
				cleaner=wr.get();
			else
				cleaner=null;
		}
		if (cleaner!=null) {
			cleaner.performCleanup();
		}

	}

	/*static boolean isCleanersEmpty()
	{
		synchronized (CleanerTools.class)
		{
			return cleaners.isEmpty();
		}
	}*/
	static boolean doesCleanersContainsThisClass(Class<? extends Cleanable.Cleaner> clazz)
	{
		synchronized (CleanerTools.class)
		{
			return cleaners.values().stream().anyMatch(c -> clazz.isAssignableFrom(c.getClass()));
		}
	}
}

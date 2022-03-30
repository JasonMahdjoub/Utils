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

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 *
 * This API aims to prevent future deactivation of finalize method calling by the garbage collector.
 * It uses Cleanable java API when JVM version is greater than Java 8.
 * Otherwise, it uses standard finalize method.
 *
 * To replace finalize method, your "finalizable" class must inherit this class.
 * Then, a constructor must call the method {@link #registerCleaner(Cleaner)} with a cleaner that
 * inherit the class {@link Cleaner}, and that must implement the method {@link Cleaner#performCleanup()}
 *
 * If you do not call the method {@link #clean()}, then the garbage collector will call it for you
 * when the object becomes unreferenced. If the JVM version is upper to Java 8, then, the Java Cleaner API is used.
 * Otherwise, it is the classical finalize method that is used.
 *
 * Please do not override method {@link #finalize()}. Otherwise, this API will be obsolete.
 *
 * @author Jason Mahdjoub
 * @version 1.0
 * @since MaDKitLanEdition 5.23.0
 */
@SuppressWarnings("deprecation")
public abstract class Cleanable implements AutoCloseable {
	public static abstract class Cleaner implements Runnable
	{
		private final AtomicBoolean cleaned=new AtomicBoolean(false);
		protected abstract void performCleanup();

		@Override
		public final void run() {
			if (cleaned.compareAndSet(false, true))
			{
				performCleanup();
			}
		}
		public final boolean isCleaned()
		{
			return cleaned.get();
		}


		@SuppressWarnings("deprecation")
		protected final void finalize()
		{
			if (JAVA_CLEANER==null) {
				run();
			}
		}
	}
	private static Object JAVA_CLEANER=null;
	private static final Method m_register;
	private static final Method m_clean;
	private static final Method m_create;
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
	private Object cleanable=null;
	private Cleaner cleaner=null;

	protected final void registerCleaner(Cleaner cleaner) {
		this.cleaner=cleaner;

		if (m_create!=null){

		synchronized (Cleanable.class)
		{
			if (JAVA_CLEANER==null)
			{
				try {
					JAVA_CLEANER=m_create.invoke(null);
				} catch (IllegalAccessException | InvocationTargetException e) {
					e.printStackTrace();
				}
				}
			}
			if (JAVA_CLEANER!=null)
			{
				try {
					cleanable=m_register.invoke(JAVA_CLEANER, this, cleaner);
				} catch (IllegalAccessException | InvocationTargetException e) {
					e.printStackTrace();
					System.exit(-1);
				}
			}
		}
	}
	protected final void clean()
	{
		if (cleanable!=null) {

			if (m_create ==null) {
				cleaner.run();
			}
			else
			{
				synchronized (Cleanable.class) {
					if (JAVA_CLEANER==null)
						cleaner.run();
					else {
						try {
							m_clean.invoke(cleanable);
						} catch (IllegalAccessException | InvocationTargetException e) {
							e.printStackTrace();
						}
					}
				}
			}
		}
	}


	public final boolean isCleaned()
	{
		return cleaner != null && cleaner.isCleaned();
	}

	@Override
	public void close() throws Exception {
		clean();
	}
}

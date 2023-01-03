/*
Copyright or © or Corp. Jason Mahdjoub (04/02/2016)

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

import java.lang.reflect.Modifier;

/**
 *
 * This API aims to prevent future deactivation of finalize method calling by the garbage collector.
 * It uses Cleanable java API when JVM version is greater than Java 8.
 * Otherwise, it uses standard finalize method.
 * <p>
 * To replace finalize method, your "finalizable" class must inherit this class.
 * Then, a constructor must call the method {@link #registerCleanerIfNotDone(Cleaner)} with a cleaner that
 * inherit the class {@link Cleaner}, and that must implement the method {@link Cleaner#performCleanup()}
 *
 * If you do not call the method {@link #clean()}, then the garbage collector will call it for you
 * when the object becomes unreferenced. If the JVM version is upper to Java 8, then, the Java Cleaner API is used.
 * Otherwise, it is the classical finalize method that is used.
 * <p>
 * Please do not override method {@link Object#finalize()}. Otherwise, this API will be obsolete.
 *
 * @author Jason Mahdjoub
 * @version 1.0
 * @since MaDKitLanEdition 5.23.0
 */
@SuppressWarnings("removal")
public interface Cleanable {

	abstract class Cleaner implements Runnable
	{
		private boolean isCleaned=false;
		private Object cleanable=null;
		private Cleaner next=null;
		CleanerTools.WR reference=null;
		protected abstract void performCleanup();


		/**
		 *
		 * @param cleanable if given cleanable is different to NULL, register this cleaner to cleanable
		 */
		protected Cleaner(Cleanable cleanable)
		{
			Class<? extends Cleaner> c=this.getClass();
			if (c.isMemberClass() && !Modifier.isStatic(c.getModifiers()))
				throw new IllegalAccessError("The class "+c+" which inherits from class "+Cleaner.class.getName()+" must be static");
			if (cleanable!=null)
			{
				CleanerTools.registerCleaner(cleanable, this);
			}
		}

		@Override
		public final void run() {
			runImpl(true);
		}

		Object getCleanable() {
			synchronized (this) {
				return cleanable;
			}
		}

		void setCleanable(Object cleanable) {
			if (cleanable==null)
				return;
			synchronized (this) {
				this.cleanable = cleanable;
			}
		}

		void setNext(Cleaner next) {
			Cleaner n=null;
			synchronized (this) {
				if (this.next!=null)
					n=this.next;
				else
					this.next = next;
			}
			if (n!=null)
				n.setNext(next);
		}
		Cleaner getNext() {
			synchronized (this) {
				return this.next;
			}
		}

		void runImpl(boolean removeFromRegister)
		{
			boolean clean=false;
			Cleaner next=null;
			synchronized (this)
			{
				if (!isCleaned)
				{
					isCleaned=true;
					cleanable=null;
					next=this.next;
					this.next=null;
					clean=true;
				}
			}
			if (clean)
			{
				if (removeFromRegister)
				{
					CleanerTools.removeCleaner(this);
				}
				try {
					if (next!=null) {
						next.runImpl(false);
					}
				}
				finally {
					performCleanup();
				}
			}
		}
		final boolean isCleaned()
		{
			synchronized (this)
			{
				return isCleaned;
			}
		}


		protected final void finalize()
		{
			if (CleanerTools.m_create==null) {
				run();
			}
		}
	}


	default void registerCleanerIfNotDone(Cleanable.Cleaner cleaner)
	{
		CleanerTools.registerCleaner(this, cleaner);
	}


	default void clean() {
		CleanerTools.clean(this);
	}


	default boolean isCleaned()
	{
		return CleanerTools.isCleaned(this);
	}


}

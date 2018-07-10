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

package com.distrimind.util.sizeof;

import java.util.HashMap;

/**
 * 
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 1.5
 */
public class ObjectSizer {

	public static class O {

	}

	protected static final HashMap<Class<?>, ClassMetaData> m_class_meta_data_cache = new HashMap<>();

	public static final int OBJECT_SHELL_SIZE_32 = 8; // java.lang.Object shell
	// size in bytes

	public static final int OBJREF_SIZE_32 = 4;

	public static final int OBJECT_SHELL_SIZE_64 = 16; // java.lang.Object shell
	// size in bytes

	public static final int OBJREF_SIZE_64 = 8;

	public static final int OBJECT_SHELL_SIZE; // java.lang.Object shell size in
	// bytes

	public static final int OBJREF_SIZE;

	public static final int LONG_FIELD_SIZE = 8;

	public static final int INT_FIELD_SIZE = 4;

	public static final int SHORT_FIELD_SIZE = 2;

	public static final int CHAR_FIELD_SIZE = 2;

	public static final int BYTE_FIELD_SIZE = 1;

	public static final int BOOLEAN_FIELD_SIZE = 1;

	public static final int DOUBLE_FIELD_SIZE = 8;

	public static final int FLOAT_FIELD_SIZE = 4;

	static {
		if (System.getProperty("os.arch").contains("64")) {
			OBJECT_SHELL_SIZE = OBJECT_SHELL_SIZE_64;
			OBJREF_SIZE = OBJREF_SIZE_64;
		} else {
			OBJECT_SHELL_SIZE = OBJECT_SHELL_SIZE_32;
			OBJREF_SIZE = OBJREF_SIZE_32;
		}

		/*
		 * OBJECT_SHELL_SIZE=(int)getObjectSize(O.class);
		 * OBJREF_SIZE=(int)getReferenceSize();
		 */
	}

	// PRIVATE //
	private static final int fSAMPLE_SIZE = 100;
	// private static long fSLEEP_INTERVAL = 1000;

	private static void collectGarbage() {
		// try {
		System.gc();
		// Thread.sleep(fSLEEP_INTERVAL);
		System.runFinalization();
		// Thread.sleep(fSLEEP_INTERVAL);
		// }
		// catch (InterruptedException ex){
		// ex.printStackTrace();
		// }
	}

	protected static ClassMetaData getClassMetaData(Class<?> o) {
		ClassMetaData res = m_class_meta_data_cache.get(o);
		if (res == null) {
			res = new ClassMetaData(o);
			synchronized (m_class_meta_data_cache) {
				m_class_meta_data_cache.put(o, res);
			}
		}
		return res;
	}

	private static long getMemoryUse() {
		putOutTheGarbage();
		long totalMemory = Runtime.getRuntime().totalMemory();

		putOutTheGarbage();
		long freeMemory = Runtime.getRuntime().freeMemory();

		return (totalMemory - freeMemory);
	}

	/**
	 * Return the approximate size in bytes, and return zero if the class has no
	 * default constructor.
	 *
	 * @param aClass
	 *            refers to a class which has a no-argument constructor.
	 * @return the size in bytes
	 */
	protected static int getObjectSize(Class<?> aClass) {
		int result = 0;

		// if the class does not have a no-argument constructor, then
		// inform the user and return 0.
		try {
			aClass.getDeclaredConstructor();
		} catch (NoSuchMethodException ex) {
			System.err.println(aClass + " does not have a no-argument constructor.");
			return result;
		}

		// this array will simply hold a bunch of references, such that
		// the objects cannot be garbage-collected
		Object[] objects = new Object[fSAMPLE_SIZE];

		// build a bunch of identical objects
		try {
			// Object throwAway = aClass.newInstance();

			long startMemoryUse = getMemoryUse();
			for (int idx = 0; idx < objects.length; ++idx) {
				objects[idx] = aClass.getDeclaredConstructor().newInstance();
			}
			long endMemoryUse = getMemoryUse();

			float approximateSize = (endMemoryUse - startMemoryUse) / (float) fSAMPLE_SIZE;
			result = Math.round(approximateSize);
		} catch (Exception ex) {
			System.err.println("Cannot create object using " + aClass);
		}
		return result;
	}

	protected static int getPrimitiveSize(final Class<?> _c) {
		if (_c == long.class)
			return LONG_FIELD_SIZE;
		else if (_c == int.class)
			return INT_FIELD_SIZE;
		else if (_c == short.class)
			return SHORT_FIELD_SIZE;
		else if (_c == char.class)
			return CHAR_FIELD_SIZE;
		else if (_c == byte.class)
			return BYTE_FIELD_SIZE;
		else if (_c == boolean.class)
			return BOOLEAN_FIELD_SIZE;
		else if (_c == double.class)
			return DOUBLE_FIELD_SIZE;
		else if (_c == float.class)
			return FLOAT_FIELD_SIZE;
		else
			throw new IllegalArgumentException("non primitive : " + _c);
	}

	/**
	 * 
	 * @return return the size of reference
	 */
	@SuppressWarnings("MismatchedReadAndWriteOfArray")
	protected static long getReferenceSize() {
		long result ;

		// this array will simply hold a bunch of references, such that
		// the objects cannot be garbage-collected
		long startMemoryUse = getMemoryUse();
		Object[] objects = new Object[fSAMPLE_SIZE];
		long endMemoryUse = getMemoryUse();
		objects[0] = null; // avoid a warning compilation

		float approximateSize = (endMemoryUse - startMemoryUse) / (float) fSAMPLE_SIZE;
		result = Math.round(approximateSize);

		return result;
	}

	private static void putOutTheGarbage() {
		collectGarbage();
		collectGarbage();
	}

	public static int sizeOf(boolean v) {
		return ObjectSizer.BOOLEAN_FIELD_SIZE;
	}

	public static int sizeOf(byte v) {
		return ObjectSizer.BYTE_FIELD_SIZE;
	}

	public static int sizeOf(char v) {
		return ObjectSizer.CHAR_FIELD_SIZE;
	}

	public static int sizeOf(double v) {
		return ObjectSizer.DOUBLE_FIELD_SIZE;
	}

	public static int sizeOf(float v) {
		return ObjectSizer.FLOAT_FIELD_SIZE;
	}

	public static int sizeOf(int v) {
		return ObjectSizer.INT_FIELD_SIZE;
	}

	public static int sizeOf(long v) {
		return ObjectSizer.LONG_FIELD_SIZE;
	}

	public static int sizeOf(Object o) {
		if (o == null)
			return 0;
		ClassMetaData c = getClassMetaData(o.getClass());
		return c.getSizeBytes(o);
	}

	public static int sizeOf(short v) {
		return ObjectSizer.SHORT_FIELD_SIZE;
	}

}

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

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.util.Arrays;

/**
 * Gives several system functions, independently from current OS running
 * 
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 3.12
 *
 */
public class StaticObjectAllocator<T> {
	private final int maxAllocations;
	private final Constructor<? extends T> constructor;
	private final Object[] allocations;
	private final boolean isByteArray;
	private static final Class<? extends byte[]> byteArrayClass=byte[].class;
	private Object[] staticArgs =new Object[0];
	public StaticObjectAllocator(int maxAllocations, Class<? extends T> concernedClass, Class<?> ...constructorParameters) throws NoSuchMethodException, SecurityException
	{
		this.maxAllocations=maxAllocations;
		isByteArray=concernedClass.equals(byteArrayClass);
		if (isByteArray)
			this.constructor=null;
		else
			this.constructor=concernedClass.getDeclaredConstructor(constructorParameters);
		this.allocations=new Object[maxAllocations];
		Arrays.fill(this.allocations, null);
	}
	
	public int getMaxAllocations()
	{
		return maxAllocations;
	}
	public void initArgs(Object ...staticArgs)
	{
		this.staticArgs=staticArgs;
	}
	public StaticAllocation<T> getNewInstance() throws InstantiationException, IllegalAccessException, IllegalArgumentException, InvocationTargetException
	{
		synchronized(this)
		{
			for (int i=0;i<allocations.length;i++)
			{
				Object o = allocations[i];
				if (o==null)
				{
					@SuppressWarnings("unchecked")
					T instance=(T)(isByteArray?new byte[(Integer)staticArgs[0]]:constructor.newInstance(staticArgs));
					StaticAllocation<T> sa=new StaticAllocation<>(instance);
					allocations[i]=sa;
					return sa;
				}
				else
				{
					@SuppressWarnings("unchecked")
					StaticAllocation<T> sa=(StaticAllocation<T>)o;
					if (!sa.used)
					{
						sa.used=true;
						return sa;
					}
				}
				
			}
			throw new OutOfMemoryError("The maximum of instances is reached : "+maxAllocations);
		}
	}
	
	
	
}

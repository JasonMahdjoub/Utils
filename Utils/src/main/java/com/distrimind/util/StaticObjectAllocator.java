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
	private final Constructor<T> constructor;
	private final Object allocations[];
	public StaticObjectAllocator(int maxAllocations, Class<T> concernedClass, Class<?> ...constructorParamters) throws NoSuchMethodException, SecurityException
	{
		this.maxAllocations=maxAllocations;
		this.constructor=concernedClass.getDeclaredConstructor(constructorParamters);
		this.allocations=new Object[maxAllocations];
		for (int i=0;i<this.allocations.length;i++)
			this.allocations[i]=null;
	}
	
	public int getMaxAllocations()
	{
		return maxAllocations;
	}
	
	public StaticAllocation<T> getNewInstance(Object ...staticArgs) throws InstantiationException, IllegalAccessException, IllegalArgumentException, InvocationTargetException
	{
		synchronized(this)
		{
			for (int i=0;i<allocations.length;i++)
			{
				Object o = allocations[i];
				if (o==null)
				{
					StaticAllocation<T> sa=new StaticAllocation<T>(constructor.newInstance(staticArgs));
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

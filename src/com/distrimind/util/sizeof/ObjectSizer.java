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

package com.distrimind.util.sizeof;

import java.util.HashMap;

/**
 * 
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 1.5
 */
public class ObjectSizer
{
    
    public static int sizeOf(Object o)
    {
	if (o==null)
	    return 0;
	ClassMetaData c=getClassMetaData(o.getClass());
	return c.getSizeBytes(o);
    }
    public static int sizeOf(int v)
    {
	return ObjectSizer.INT_FIELD_SIZE;
    }
    public static int sizeOf(char v)
    {
	return ObjectSizer.CHAR_FIELD_SIZE;
    }
    public static int sizeOf(byte v)
    {
	return ObjectSizer.BYTE_FIELD_SIZE;
    }
    public static int sizeOf(short v)
    {
	return ObjectSizer.SHORT_FIELD_SIZE;
    }
    public static int sizeOf(boolean v)
    {
	return ObjectSizer.BOOLEAN_FIELD_SIZE;
    }
    public static int sizeOf(long v)
    {
	return ObjectSizer.LONG_FIELD_SIZE;
    }
    public static int sizeOf(float v)
    {
	return ObjectSizer.FLOAT_FIELD_SIZE;
    }
    public static int sizeOf(double v)
    {
	return ObjectSizer.DOUBLE_FIELD_SIZE;
    }
    
    protected static final HashMap<Class<?>, ClassMetaData> m_class_meta_data_cache=new HashMap<Class<?>, ClassMetaData>();
    
    protected static ClassMetaData getClassMetaData(Class<?> o)
    {
	ClassMetaData res=m_class_meta_data_cache.get(o);
	if (res==null)
	{
	    res=new ClassMetaData(o);
	    synchronized (m_class_meta_data_cache)
	    {
		m_class_meta_data_cache.put(o, res);
	    }
	}
	return res;
    }
    
    
    protected static int getPrimitiveSize(final Class<?> _c)
    {
	if (_c==long.class)
	    return LONG_FIELD_SIZE;
	else if (_c==int.class)
	    return INT_FIELD_SIZE;
	else if (_c==short.class)
	    return SHORT_FIELD_SIZE;
	else if (_c==char.class)
	    return CHAR_FIELD_SIZE;
	else if (_c==byte.class)
	    return BYTE_FIELD_SIZE;
	else if (_c==boolean.class)
	    return BOOLEAN_FIELD_SIZE;
	else if (_c==double.class)
	    return DOUBLE_FIELD_SIZE;
	else if (_c==float.class)
	    return FLOAT_FIELD_SIZE;
	else
	    throw new IllegalArgumentException("non primitive : "+_c);
    }
    
    
    
    public static final int OBJECT_SHELL_SIZE_32   = 8; // java.lang.Object shell size in bytes
    public static final int OBJREF_SIZE_32         = 4;

    public static final int OBJECT_SHELL_SIZE_64   = 16; // java.lang.Object shell size in bytes
    public static final int OBJREF_SIZE_64         = 8;
    
    public static final int OBJECT_SHELL_SIZE   ; // java.lang.Object shell size in bytes
    public static final int OBJREF_SIZE         ;
    
    public static final int LONG_FIELD_SIZE     = 8;
    public static final int INT_FIELD_SIZE      = 4;
    public static final int SHORT_FIELD_SIZE    = 2;
    public static final int CHAR_FIELD_SIZE     = 2;
    public static final int BYTE_FIELD_SIZE     = 1;
    public static final int BOOLEAN_FIELD_SIZE  = 1;
    public static final int DOUBLE_FIELD_SIZE   = 8;
    public static final int FLOAT_FIELD_SIZE    = 4;

    static{
	if (System.getProperty("os.arch").contains("64"))
	{
	    OBJECT_SHELL_SIZE=OBJECT_SHELL_SIZE_64;
	    OBJREF_SIZE=OBJREF_SIZE_64;
	}
	else
	{
	    OBJECT_SHELL_SIZE=OBJECT_SHELL_SIZE_32;
	    OBJREF_SIZE=OBJREF_SIZE_32;
	}
	    
	/*OBJECT_SHELL_SIZE=(int)getObjectSize(O.class);
	OBJREF_SIZE=(int)getReferenceSize();*/
    }
    public static class O extends Object
    {
	
    }

    /**
     * 
     * @return return the size of reference
     */
  protected static long getReferenceSize()
  {
      long result = 0;

      //this array will simply hold a bunch of references, such that
      //the objects cannot be garbage-collected
      long startMemoryUse = getMemoryUse();
      Object[] objects = new Object[fSAMPLE_SIZE];
      long endMemoryUse = getMemoryUse();
      objects[0]=null; //avoid a warning compilation
      
      float approximateSize = ( endMemoryUse - startMemoryUse ) /(float)fSAMPLE_SIZE;
      result = Math.round( approximateSize );

      return result;
  }
  
  
  /**
  * Return the approximate size in bytes, and return zero if the class
  * has no default constructor.
  *
  * @param aClass refers to a class which has a no-argument constructor.
  * @return the size in bytes
  */
  protected static int getObjectSize( Class<?> aClass ){
    int result = 0;

    //if the class does not have a no-argument constructor, then
    //inform the user and return 0.
    try {
      aClass.getConstructor( new Class[]{} );
    }
    catch ( NoSuchMethodException ex ) {
      System.err.println(aClass + " does not have a no-argument constructor.");
      return result;
    }

    //this array will simply hold a bunch of references, such that
    //the objects cannot be garbage-collected
    Object[] objects = new Object[fSAMPLE_SIZE];

    //build a bunch of identical objects
    try {
      //Object throwAway = aClass.newInstance();

      long startMemoryUse = getMemoryUse();
      for (int idx=0; idx < objects.length ; ++idx) {
        objects[idx] = aClass.newInstance();
      }
      long endMemoryUse = getMemoryUse();

      float approximateSize = ( endMemoryUse - startMemoryUse ) /(float)fSAMPLE_SIZE;
      result = Math.round( approximateSize );
    }
    catch (Exception ex) {
      System.err.println("Cannot create object using " + aClass);
    }
    return result;
  }

  // PRIVATE //
  private static final int fSAMPLE_SIZE = 100;
  //private static long fSLEEP_INTERVAL = 1000;
  
  private static long getMemoryUse(){
    putOutTheGarbage();
    long totalMemory = Runtime.getRuntime().totalMemory();

    putOutTheGarbage();
    long freeMemory = Runtime.getRuntime().freeMemory();

    return (totalMemory - freeMemory);
  }

  private static void putOutTheGarbage() {
    collectGarbage();
    collectGarbage();
  }

  private static void collectGarbage() {
      //try {
	  System.gc();
	  //Thread.sleep(fSLEEP_INTERVAL);
	  System.runFinalization();
	  //Thread.sleep(fSLEEP_INTERVAL);
    //}
    //catch (InterruptedException ex){
      //ex.printStackTrace();
    //}
  }
    
}

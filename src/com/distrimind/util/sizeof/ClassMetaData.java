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

import java.lang.reflect.Array;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.security.AccessController;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedList;

/**
 * 
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 1.5
 */
final class ClassMetaData
{
    protected static final class ClassAccessPrivilegedAction implements PrivilegedExceptionAction<Object>
    {
	private Class<?> m_cls;

	@Override
	public Object run() throws Exception
	{
	    return m_cls.getDeclaredFields();
	}

	public void setContext(final Class<?> cls)
	{
	    m_cls = cls;
	}
    }

    protected static final class FieldAccessPrivilegedAction implements PrivilegedExceptionAction<Object>
    {
	private Field m_field;

	@Override
	public Object run() throws Exception
	{
	    m_field.setAccessible(true);

	    return null;
	}

	public void setContext(final Field field)
	{
	    m_field = field;
	}
    }

    protected static class PersonalField
    {
	public final Field m_field;

	public final int m_depth;

	PersonalField(Field _f)
	{
	    m_field = _f;
	    m_depth = -1;
	}

	PersonalField(Field _f, int _depth)
	{
	    m_field = _f;
	    m_depth = _depth;
	}
    }

    protected static final ClassAccessPrivilegedAction capa = new ClassAccessPrivilegedAction();

    protected static final FieldAccessPrivilegedAction fapa = new FieldAccessPrivilegedAction();

    private Class<?> m_class;

    private ArrayList<PersonalField> m_fields = new ArrayList<PersonalField>();

    private ArrayList<Field> m_fields_collection = new ArrayList<Field>();

    // private ArrayList<Field> m_arrays=new ArrayList<Field>();
    private int m_size = 0;

    @SuppressWarnings("unchecked")
    public ClassMetaData(Class<?> _c)
    {
	m_class = _c;
	if (_c.isPrimitive())
	{
	    m_size = ObjectSizer.getPrimitiveSize(_c);
	}
	else if (_c.isArray())
	{
	    m_size = ObjectSizer.OBJECT_SHELL_SIZE + ObjectSizer.INT_FIELD_SIZE;
	}
	else
	{
	    m_size = ObjectSizer.OBJECT_SHELL_SIZE;

	    Field fields[];
	    synchronized (capa)
	    {
		capa.setContext(m_class);
		try
		{
		    fields = (Field[]) AccessController.doPrivileged(capa);
		}
		catch (PrivilegedActionException e)
		{
		    throw new RuntimeException(
			    "could not access declared fields of class "
				    + m_class.getName() + ": "
				    + e.getException());
		}
	    }
	    ArrayList<Field> fields_to_avoid = null;
	    for (Field f : fields)
	    {
		if ((f.getModifiers() & Modifier.STATIC) != 0
			&& (f.getModifiers() & Modifier.PUBLIC) != 0)
		{
		    if (f.getName().contains("m_not_to_compute_size_fields"))
		    {
			if (f.getType() == (new ArrayList<Field>()).getClass())
			{
			    try
			    {
				fields_to_avoid = (ArrayList<Field>) f
					.get(null);
			    }
			    catch (IllegalArgumentException e)
			    {
				throw new RuntimeException(
					"could not make get static field m_not_computed_size_fields: "
						+ e);
			    }
			    catch (IllegalAccessException e)
			    {
				throw new RuntimeException(
					"could not make get static field m_not_computed_size_fields: "
						+ e);
			    }
			    break;
			}
		    }
		}
	    }
	    for (Field f : fields)
	    {
		if ((f.getModifiers() & Modifier.STATIC) != 0)
		    continue;
		Class<?> fieldType = f.getType();
		if (fieldType.isPrimitive())
		{
		    m_size += ObjectSizer.getPrimitiveSize(fieldType);
		}
		else
		{
		    if (!f.isAccessible())
		    {
			synchronized (fapa)
			{
			    fapa.setContext(f);
			    try
			    {
				AccessController.doPrivileged(fapa);
			    }
			    catch (PrivilegedActionException e)
			    {
				throw new RuntimeException(
					"could not make field " + f
						+ " accessible: "
						+ e.getException());
			    }
			}
		    }
		    m_size += ObjectSizer.OBJREF_SIZE;

		    if ((fields_to_avoid == null || (fields_to_avoid != null
			    && !fields_to_avoid.contains(f))))
		    {
			DontComputeSize a = f
				.getAnnotation(DontComputeSize.class);
			if (a == null)
			{
			    DontComputeSizeForInnerCollectionElements d = f
				    .getAnnotation(
					    DontComputeSizeForInnerCollectionElements.class);
			    if (d == null)
				m_fields.add(new PersonalField(f));
			    else
			    {
				if (f.getType().isArray())
				    m_fields.add(new PersonalField(f, 1));
				else if (Collection.class
					.isAssignableFrom(f.getType()))
				{
				    m_fields_collection.add(f);
				}
				else
				    m_fields.add(new PersonalField(f));

			    }
			}
			else
			{
			    if (a.depth() > 0)
				m_fields.add(new PersonalField(f, a.depth()));
			}
		    }
		}
	    }
	}

	Class<?> superClass = _c.getSuperclass();
	if (superClass != null)
	{
	    ClassMetaData cmdsuper = new ClassMetaData(superClass);
	    m_size += cmdsuper.m_size - ObjectSizer.OBJECT_SHELL_SIZE;
	    m_fields.addAll(cmdsuper.m_fields);
	}
    }

    public boolean equals(ClassMetaData _c)
    {
	return m_class == _c.m_class;
    }

    @Override
    public boolean equals(Object _o)
    {
	return this.equals((ClassMetaData) _o);
    }

    public int getSizeBytes(Object _instance)
    {
	if (_instance == null)
	    return 0;
	if (_instance.getClass() != m_class)
	    throw new IllegalArgumentException(
		    "the object instance does not correspond to this class meta data");
	if (m_class.isPrimitive())
	    return m_size;
	LinkedList<Object> visited = new LinkedList<Object>();

	return getSizeBytes(_instance, visited, -1);
    }

    protected int getSizeBytes(Object _instance, LinkedList<Object> visited, int depth)
    {
	if (_instance == null)
	    return 0;
	for (Object o : visited)
	    if (o == _instance)
		return 0;
	visited.add(_instance);
	int size = m_size;
	if (m_class.isArray())
	{
	    Class<?> comp = m_class.getComponentType();
	    int size_array = Array.getLength(_instance);
	    if (comp.isPrimitive())
	    {
		size += ObjectSizer.getPrimitiveSize(comp) * size_array;
	    }
	    else
	    {
		size += ObjectSizer.OBJREF_SIZE * size_array;
		if (depth != 0)
		{
		    for (int i = 0; i < size_array; i++)
		    {
			Object obj_array = Array.get(_instance, i);
			if (obj_array != null)
			{
			    ClassMetaData c = ObjectSizer
				    .getClassMetaData(obj_array.getClass());
			    if (depth != -1)
				size += c.getSizeBytes(obj_array, visited,
					depth - 1);
			    else
				size += c.getSizeBytes(obj_array, visited,
					depth);
			}
		    }
		}
	    }
	}
	else
	{
	    if (depth > 0 || depth == -1)
	    {
		for (PersonalField f : m_fields)
		{
		    Object obj;
		    try
		    {
			obj = f.m_field.get(_instance);
		    }
		    catch (IllegalArgumentException e)
		    {
			throw new RuntimeException(
				"could not access declared fields of class "
					+ m_class.getName() + " with instance "
					+ _instance + ": " + e);
		    }
		    catch (IllegalAccessException e)
		    {
			throw new RuntimeException(
				"could not access declared fields of class "
					+ m_class.getName() + " with instance "
					+ _instance + ": " + e);
		    }
		    if (obj != null)
		    {
			ClassMetaData c = ObjectSizer
				.getClassMetaData(obj.getClass());
			if (depth != -1)
			{
			    if (f.m_depth > 0)
			    {
				size += c.getSizeBytes(obj, visited,
					Math.min(depth - 1, f.m_depth - 1));
			    }
			    else
			    {
				size += c.getSizeBytes(obj, visited, depth - 1);
			    }
			}
			else
			    size += c.getSizeBytes(obj, visited,
				    f.m_depth > 0 ? f.m_depth - 1 : -1);
		    }
		}
		for (Field f : m_fields_collection)
		{
		    Collection<?> obj;
		    try
		    {
			obj = (Collection<?>) f.get(_instance);
		    }
		    catch (IllegalArgumentException e)
		    {
			throw new RuntimeException(
				"could not access declared fields of class "
					+ m_class.getName() + " with instance "
					+ _instance + ": " + e);
		    }
		    catch (IllegalAccessException e)
		    {
			throw new RuntimeException(
				"could not access declared fields of class "
					+ m_class.getName() + " with instance "
					+ _instance + ": " + e);
		    }
		    if (obj != null)
		    {
			for (Object o : obj)
			{
			    visited.add(o);
			}
			ClassMetaData c = ObjectSizer
				.getClassMetaData(obj.getClass());
			if (depth != -1)
			    size += c.getSizeBytes(obj, visited, depth - 1);
			else
			    size += c.getSizeBytes(obj, visited, -1);
		    }
		}
	    }
	}
	return size;
    }

    @Override
    public int hashCode()
    {
	return m_class.hashCode();
    }

}

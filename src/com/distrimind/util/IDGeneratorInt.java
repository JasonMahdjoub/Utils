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

import java.io.Serializable;

/**
 * Represent a set of unique identifiers until they are released.
 * 
 * @author Jason Mahdjoub
 * @version 1.1
 * @since Utils 1.0
 * 
 *
 */
public final class IDGeneratorInt implements Serializable
{
    /**
     * 
     */
    private static final long serialVersionUID = 6578160385229331890L;

    private int[] m_ids;

    private int m_size = 0;

    private final int m_reserve_max;

    // private final int m_id_start;
    private int m_last_id;
    private final int idStart;

    public IDGeneratorInt()
    {
	this(20, 0);
    }

    int getRealTabSize()
    {
	return m_ids.length;
    }
    
    public int getNumberOfMemorizedIds()
    {
	return m_size;
    }
    
    public IDGeneratorInt(int _id_start)
    {
	this(20, _id_start);
    }

    public IDGeneratorInt(int _reserve_max, int _id_start)
    {
	// m_id_start=_id_start;
	if (_reserve_max < 0)
	    _reserve_max = 0;
	m_reserve_max = _reserve_max;
	m_ids = new int[m_reserve_max];
	m_last_id = _id_start - 1;
	idStart=_id_start;
    }

    public int getNewID()
    {
	int res = ++m_last_id;
	int i = -1;
	if (m_size > 0)
	{
	    if (m_ids[0] > res)
		i = 0;
	    else if (m_ids[m_size - 1] < res)
		i = m_size;
	}
	if (i == -1)
	{
	    for (i = 0; i < m_size; ++i, ++res)
		if (m_ids[i] > res)
		    break;
	}
	if (i < m_size)
	{
	    if (getReserve() > 0)
	    {
		for (int j = m_size; j > i; j--)
		{
		    m_ids[j] = m_ids[j - 1];
		}
		m_ids[i] = res;
		++m_size;
	    }
	    else
	    {
		int[] ids = new int[m_size + m_reserve_max + 1];
		System.arraycopy(m_ids, 0, ids, 0, i);
		ids[i] = res;
		System.arraycopy(m_ids, i + 1, ids, i, m_size - i);
		m_ids = ids;
		++m_size;
	    }
	}
	else
	{
	    if (getReserve() <= 0)
	    {
		int[] ids = new int[m_size + m_reserve_max + 1];
		System.arraycopy(m_ids, 0, ids, 0, m_size);
		m_ids = ids;
	    }
	    m_ids[m_size++] = res;
	}
	return res;
    }

    private int getReserve()
    {
	return m_ids.length - m_size;
    }

    public boolean hasID(int _val)
    {
	for (int i = 0; i < m_size && m_ids[i] <= _val; i++)
	{
	    if (m_ids[i] == _val)
		return true;
	}
	return false;
    }

    public boolean removeID(int _val)
    {
	int i;
	for (i = 0; i < m_size && m_ids[i] < _val; i++)
	{
	}
	if (i < m_size && m_ids[i] == _val)
	{
	    if (getReserve() > m_reserve_max * 2)
	    {
		int[] ids = new int[m_size + m_reserve_max];
		if (i>0)
		    System.arraycopy(m_ids, 0, ids, 0, i);
		int s = m_size - i - 1;
		if (s > 0)
		    System.arraycopy(m_ids, i+1, ids, i, s);
		m_ids = ids;
		--m_size;
	    }
	    else
	    {
		for (int j = i + 1; j < m_size; j++)
		{
		    m_ids[j - 1] = m_ids[j];
		}
		--m_size;
	    }
	    if (m_size>0)
		m_last_id=m_ids[m_size-1];
	    else
		m_last_id=idStart-1;
	    return true;
	}
	return false;
    }

}

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

package com.distrimind.util.version;

import com.distrimind.util.properties.XMLProperties;

/**
 * Represents a Person participating to a software creation
 * 
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 1.0
 * @see Version
 * @see PersonDeveloper
 */
public class Person extends XMLProperties {
	/**
	 * 
	 */
	private static final long serialVersionUID = 6907388594593576340L;

	protected String m_name, m_first_name;

	protected Person() {
		this("", "");
	}

	public Person(String _name, String _first_name) {
		super(null);
		if (_name == null)
			throw new NullPointerException("_name");
		if (_first_name == null)
			throw new NullPointerException("_first_name");
		m_name = _name.toUpperCase();
		if (_first_name.length() > 0)
			m_first_name = _first_name.substring(0, 1).toUpperCase() + _first_name.substring(1).toLowerCase();
		else
			m_first_name = "";
	}

	@Override
	public int hashCode()
	{
		return m_name.hashCode()+m_first_name.hashCode();
	}
	
	@Override
	public boolean equals(Object o) {
		if (o == null)
			return false;
		if (o == this)
			return true;
		if (o instanceof Person) {
			Person p = ((Person) o);
			return m_first_name.equals(p.m_first_name) && m_name.equals(p.m_name);
		}
		return false;
	}

	public String getFirstName() {
		return m_first_name;
	}

	public String getName() {
		return m_name;
	}

	@Override
	public String toString() {
		return m_first_name + " " + m_name;
	}

}

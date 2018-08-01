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

import java.text.DateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.Locale;

import com.distrimind.util.properties.MultiFormatProperties;
import com.distrimind.util.version.Version.Type;

/**
 * Represents the description of program version
 * 
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 1.5
 * @see Version
 */
public class Description extends MultiFormatProperties {

	/**
	 * 
	 */
	private static final long serialVersionUID = -5480559682819518935L;

	private ArrayList<String> m_items = new ArrayList<>();

	private short m_major = 0;

	private short m_minor = 0;

	private short m_revision = 0;

	private Version.Type m_type = null;

	private short m_alpha_beta_version = 0;

	private Date m_date;

	protected Description() {
		this((short)0, (short)0, (short)0, Version.Type.Alpha, (short)0, new Date());
	}

	public Description(short _major, short _minor, short _revision, Version.Type _type, short _alpha_beta_version, Date _date) {
		super(null);
		if (_date == null)
			throw new NullPointerException("_date");
		m_major = _major;
		m_minor = _minor;
		m_revision = _revision;
		m_type = _type;
		m_alpha_beta_version = _alpha_beta_version;
		m_date = _date;
	}

	@Override
	public int hashCode()
	{
		return m_major<<24+m_minor<<16+m_revision<<8+m_alpha_beta_version;
	}
	
	public void addItem(String d) {
		if (d == null)
			throw new NullPointerException();
		m_items.add(d);
	}

	@Override
	public boolean equals(Object o) {
		if (o == null)
			return false;
		if (o == this)
			return true;
		if (o instanceof Description) {
			Description d = (Description) o;
			return d.m_alpha_beta_version == m_alpha_beta_version && d.m_date.equals(m_date)
					&& d.m_items.equals(m_items) && d.m_major == m_major && d.m_minor == m_minor
					&& d.m_revision == m_revision && d.m_type.equals(m_type);
		}
		return false;
	}

	public short getAlphaBetaVersion() {
		return m_alpha_beta_version;
	}

	public Date getDate() {
		return m_date;
	}

	public String getHTML() {
		StringBuilder s = new StringBuilder();
		s.append("<BR><H2>").append(m_major).append(".").append(m_minor).append(".").append(m_revision).append(" ").append(m_type).append((m_type.equals(Type.Alpha) || m_type.equals(Type.Beta))
				? " " + Integer.toString(m_alpha_beta_version)
				: "").append(" (").append(DateFormat.getDateInstance(DateFormat.SHORT, Locale.FRANCE).format(m_date)).append(")</H2>");
		s.append("<ul>");
		for (String d : m_items) {
			s.append("<li>");
			s.append(d);
			s.append("</li>");
		}
		s.append("</ul>");
		return s.toString();
	}

	public String getMarkdownCode() {
		StringBuilder s = new StringBuilder();
		s.append("\n");
		s.append("### ").append(m_major).append(".").append(m_minor).append(".").append(m_revision).append(" ").append(m_type).append((m_type.equals(Type.Alpha) || m_type.equals(Type.Beta))
				? " " + Integer.toString(m_alpha_beta_version)
				: "").append(" (").append(DateFormat.getDateInstance(DateFormat.SHORT, Locale.FRANCE).format(m_date)).append(")");
		s.append("\n");
		for (String d : m_items) {
			s.append("* ");
			s.append(d);
			s.append("\n");
		}
		
		return s.toString();
	}
	public ArrayList<String> getItems() {
		return m_items;
	}

	public short getMajor() {
		return m_major;
	}

	public short getMinor() {
		return m_minor;
	}

	public short getRevision() {
		return m_revision;
	}

	public Type getType() {
		return m_type;
	}
}

/*
 * Utils is created and developped by Jason MAHDJOUB (jason.mahdjoub@distri-mind.fr) at 2016.
 * MadKitGroup extension was developped by Jason Mahdjoub. 
 * Individual contributors are indicated by the @authors tag.
 * 
 * This file is part of Utils.
 * 
 * This is free software; you can redistribute it and/or modify it under the
 * terms of the GNU General Public License Lesser as published by the Free
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

package com.distrimind.util.version;

import java.text.DateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.Locale;

import org.w3c.dom.Document;
import org.w3c.dom.Node;

import com.distrimind.util.properties.XMLProperties;
import com.distrimind.util.version.Version.Type;

/**
 * Represents the description of program version
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 1.0
 * @see Version
 */
public class Description extends XMLProperties
{
    
    /**
     * 
     */
    private static final long serialVersionUID = -5480559682819518935L;
    
    
    private ArrayList<String> m_items=new ArrayList<String>();
    private int m_major=0;
    private int m_minor=0;
    private int m_revision=0;
    private Version.Type m_type=null;
    private int m_alpha_beta_version=0;
    private Date m_date;
    
    public Description()
    {
	this(0,0,0,Version.Type.Alpha, 0, new Date());
    }
    public Description(int _major, int _minor, int _revision, Version.Type _type, int _alpha_beta_version, Date _date)
    {
	super(null);
	m_major=_major;
	m_minor=_minor;
	m_revision=_revision;
	m_type=_type;
	m_alpha_beta_version=_alpha_beta_version;
	m_date=_date;
    }
    public int getMajor()
    {
	return m_major;
    }
    public int getMinor()
    {
	return m_minor;
    }
    public int getRevision()
    {
	return m_revision;
    }
    public Type getType()
    {
	return m_type;
    }
    
    public int getAlphaBetaVersion()
    {
	return m_alpha_beta_version;
    }
    public Date getDate()
    {
	return m_date;
    }
    public void addItem(String d)
    {
	m_items.add(d);
    }
    public ArrayList<String> getItems()
    {
	return m_items;
    }
    public String getHTML()
    {
	StringBuffer s=new StringBuffer();
	s.append("<BR><H2>"+m_major+"."+m_minor+"."+m_revision+" "+m_type+((m_type.equals(Type.Alpha) || m_type.equals(Type.Beta))?" "+Integer.toString(m_alpha_beta_version):"")+" ("+DateFormat.getDateInstance(DateFormat.SHORT, Locale.FRANCE).format(m_date)+")</H2>");
	s.append("<ul>");
	for (String d : m_items)
	{
	    s.append("<li>");
	    s.append(d);
	    s.append("</li>");
	}
	s.append("</ul>");
	return s.toString();
    }

    @Override
    public Node getRootNode(Document _document)
    {
	for (int i=0;i<_document.getChildNodes().getLength();i++)
	{
	    Node n=_document.getChildNodes().item(i);
	    if (n.getNodeName().equals(Version.class.getName()))
		return n;
	}
	return null;
    }
	

    @Override
    public Node createOrGetRootNode(Document _document)
    {
	Node res=getRootNode(_document);
	if (res==null)
	{
	    res=_document.createElement(Version.class.getName());
	    _document.appendChild(res);
	}
	return res;
    }

}

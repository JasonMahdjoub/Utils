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

import org.w3c.dom.Document;
import org.w3c.dom.Node;

import com.distrimind.util.properties.XMLProperties;

/**
 * Represents a Person participating to a software creation
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 1.0
 * @see Version
 * @see PersonDeveloper
 */
public class Person extends XMLProperties
{
    /**
     * 
     */
    private static final long serialVersionUID = 6907388594593576340L;
    
    protected String m_name, m_first_name;
    
    public Person()
    {
	this("", "");
    }
    public Person(String _name, String _first_name)
    {
	super(null);
	m_name=_name.toUpperCase();
	if (_first_name.length()>0)
	    m_first_name=_first_name.substring(0,1).toUpperCase()+_first_name.substring(1).toLowerCase();
	else 
	    m_first_name="";
    }

    public String getFirstName()
    {
	return m_first_name;
    }

    public String getName()
    {
	return m_name;
    }
    
    @Override public String toString()
    {
	return m_first_name+" "+m_name;
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

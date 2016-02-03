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
import java.util.Date;
import java.util.Locale;
/**
 * Represents a person developing a software
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 1.0
 * @see Version
 * @see Person
 */
public class PersonDeveloper extends Person
{
    /**
     * 
     */
    private static final long serialVersionUID = 6519819432111179436L;
    
    private Date m_date_begin_development;
    
    public PersonDeveloper(String _name, String _first_name, Date _date_begin_development)
    {
	super(_name, _first_name);
	m_date_begin_development=_date_begin_development;
    }
    
    public Date getDateBeginDevelopment()
    {
	return m_date_begin_development;
    }
    
    @Override public String toString()
    {
	
	return m_first_name+" "+m_name+" (Entred in the team at "+DateFormat.getDateInstance(DateFormat.SHORT, Locale.FRANCE).format(m_date_begin_development)+")";
    }
    
}

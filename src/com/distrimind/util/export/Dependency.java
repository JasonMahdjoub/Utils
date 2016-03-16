/*
 * MadKitGroupExtension (created by Jason MAHDJOUB (jason.mahdjoub@free.fr)) Copyright (c)
 * 2012. Individual contributors are indicated by the @authors tag.
 * 
 * This file is part of MadKitGroupExtension.
 * 
 * This is free software; you can redistribute it and/or modify it under the
 * terms of the GNU General Public License as published by the Free
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
package com.distrimind.util.export;

import com.distrimind.util.properties.XMLProperties;
/**
 * 
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 1.0
 */

public abstract class Dependency extends XMLProperties
{
    
    /**
     * 
     */
    private static final long serialVersionUID = -184485775056554728L;

    protected Dependency()
    {
	super(null);
    }

    public static String getDefaultBinaryExcludeRegex()
    {
	return "\\.java$";
    }

    public static String getDefaultBinaryIncludeRegex()
    {
	return null;
    }
    public static String getDefaultSourceExcludeRegex()
    {
	return "\\.class$";
    }

    public static String getDefaultSourceIncludeRegex()
    {
	return null;
    }
    
    public static String getRegexMatchPackage(Package p)
    {
	return mixRegexes(".*"+p.getName().replace(".", "/")+".*", ".*"+p.getName().replace(".", "\\\\")+".*");
    }
    
    

    public static String getRegexMatchClass(Class<?> c)
    {
	return mixRegexes(".*"+c.getCanonicalName().replace(".", "/")+".*", ".*"+c.getCanonicalName().replace(".", "\\\\")+".*");
    }
    
    public static String mixRegexes(String regex1, String regex2, String ...regexes)
    {
	StringBuffer sb=new StringBuffer();
	sb.append(regex1);
	sb.append("|");
	sb.append(regex2);
	for (String s : regexes)
	{
	    sb.append("|");
	    sb.append(s);
	}
	return sb.toString();
    }

}

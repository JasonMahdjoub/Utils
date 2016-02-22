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
package com.distrimind.util;

import java.io.InputStream;
import java.util.Calendar;

import com.distrimind.util.export.License;
import com.distrimind.util.version.Description;
import com.distrimind.util.version.Person;
import com.distrimind.util.version.PersonDeveloper;
import com.distrimind.util.version.Version;

/**
 * 
 * @author Jason Mahdjoub
 * @version 1.3
 */
public class Utils
{
    public static final Version VERSION;
    public static final License LICENSE=new License(License.PredefinedLicense.GNU_LGPL_v3_0);
    static
    {
	Calendar c=Calendar.getInstance();
	c.set(2016, 1, 4);
	Calendar c2=Calendar.getInstance();
	c.set(2016, 1, 22);
    	VERSION=new Version("Utils", 1,3,0, Version.Type.Stable, 0, c.getTime(), c2.getTime());
	try
	{
	
	    InputStream is=Utils.class.getResourceAsStream("build.txt");
	    VERSION.loadBuildNumber(is);
	
	    VERSION.addCreator(new Person("mahdjoub", "jason"));
	    c=Calendar.getInstance();
	    c.set(2016, 1, 4);
	    VERSION.addDeveloper(new PersonDeveloper("mahdjoub", "jason", c.getTime()));
	
	    c=Calendar.getInstance();
	    c.set(2016, 1, 22);
	    Description d=new Description(1,3,0,Version.Type.Stable, 0, c.getTime());
	    d.addItem("Adding SecuredDecentralizedID class");
	    VERSION.addDescription(d);

	    c=Calendar.getInstance();
	    c.set(2016, 1, 15);
	    d=new Description(1,2,0,Version.Type.Stable, 0, c.getTime());
	    d.addItem("Adding function AbstractXMLObjectParser.isValid(Class)");
	    d.addItem("Correcting export bug : temporary files were not deleted.");
	    VERSION.addDescription(d);
	    
	    c=Calendar.getInstance();
	    c.set(2016, 1, 14);
	    d=new Description(1,1,0,Version.Type.Stable, 0, c.getTime());
	    d.addItem("Adding some internal modifications to ReadWriteLocker");
	    VERSION.addDescription(d);

	    c=Calendar.getInstance();
	    c.set(2016, 1, 4);
	    d=new Description(1,0,0,Version.Type.Stable, 0, c.getTime());
	    d.addItem("Realeasing first version of Utils");
	    VERSION.addDescription(d);
	}
	catch(Exception e)
	{
	    e.printStackTrace();
	}
    }
    
}

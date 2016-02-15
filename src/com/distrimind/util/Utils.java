package com.distrimind.util;

import java.io.InputStream;
import java.util.Calendar;

import com.distrimind.util.export.License;
import com.distrimind.util.version.Description;
import com.distrimind.util.version.Person;
import com.distrimind.util.version.PersonDeveloper;
import com.distrimind.util.version.Version;

public class Utils
{
    public static final Version VERSION;
    public static final License LICENSE=new License(License.PredefinedLicense.GNU_LGPL_v3_0);
    static
    {
	Calendar c=Calendar.getInstance();
	c.set(2016, 1, 4);
	Calendar c2=Calendar.getInstance();
	c.set(2016, 1, 15);
    	VERSION=new Version("Utils", 1,2,0, Version.Type.Stable, 0, c.getTime(), c2.getTime());
	try
	{
	
	    InputStream is=Utils.class.getResourceAsStream("build.txt");
	    VERSION.loadBuildNumber(is);
	
	    VERSION.addCreator(new Person("mahdjoub", "jason"));
	    c=Calendar.getInstance();
	    c.set(2016, 1, 4);
	    VERSION.addDeveloper(new PersonDeveloper("mahdjoub", "jason", c.getTime()));
	
	    c=Calendar.getInstance();
	    c.set(2016, 1, 15);
	    Description d=new Description(1,2,0,Version.Type.Stable, 0, c.getTime());
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

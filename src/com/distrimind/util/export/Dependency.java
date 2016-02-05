package com.distrimind.util.export;

import com.distrimind.util.properties.XMLProperties;

public class Dependency extends XMLProperties
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

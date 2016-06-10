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

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

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.ArrayList;
import java.util.List;
import java.util.jar.JarFile;
import java.util.zip.ZipEntry;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;

import org.testng.TestNG;
import org.testng.xml.XmlClass;
import org.testng.xml.XmlSuite;
import org.testng.xml.XmlTest;

import com.distrimind.util.export.Suite.TestClass;
/**
 * 
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 1.6
 */
public class TestNGFile extends AbstractUnitTests
{
    /**
     * 
     */
    private static final long serialVersionUID = -4768424427517680853L;
    
    private String relative_file_name;
    private boolean xmlFile;
    
    public TestNGFile()
    {
	
    }
    
    public TestNGFile(Package p, String xml_file_name)
    {
	relative_file_name=p.getName().replace('.', '/')+"/"+xml_file_name;
	xmlFile=true;
    }

    public TestNGFile(Class<?> class_name)
    {
	relative_file_name=class_name.getCanonicalName();
	xmlFile=false;
    }
    
    @Override
    public boolean executeTestsFromJarFile(File jarFile) throws ClassNotFoundException, IOException
    {
	if (xmlFile)
	    return runSuite(jarFile, getTestSuiteFromJar(jarFile, relative_file_name));
	else
	{
	    URL[] urls={jarFile.toURI().toURL()};
	    return runSuite(new URLClassLoader(urls), relative_file_name);
	}
    }
    
    @Override
    public boolean executeTestsFromSystemClassLoader() throws ClassNotFoundException, JAXBException
    {
	if (xmlFile)
	    return runSuite(ClassLoader.getSystemClassLoader(), parseSuite(ClassLoader.getSystemResourceAsStream(relative_file_name)));
	else
	    return runSuite(ClassLoader.getSystemClassLoader(), relative_file_name);
	    
    }

    private Suite getTestSuiteFromJar(File jarFile, String filename) {
	
	    Suite suite = null;
	    try {
	        if (jarFile.isFile()) {
	            final JarFile jar = new JarFile(jarFile);

	            try
	            {
	        	InputStream in = jar.getInputStream(new ZipEntry(filename));
	        	try
	        	{
	        	    suite = parseSuite(in);
	        	}
	        	finally
	        	{
	        	    in.close();
	        	}
	            }
	            finally
	            {
	        	jar.close();
	            }
	        }

	    } catch (IOException | JAXBException e) {
	        e.printStackTrace();
	    }
	    return suite;
	}

    private Suite parseSuite(InputStream is) throws JAXBException {
	JAXBContext jaxbContext = JAXBContext.newInstance(Suite.class);
	    Unmarshaller jaxbUnmarshaller = jaxbContext.createUnmarshaller();
	    return (Suite) jaxbUnmarshaller.unmarshal(is);
    }    
    
    
    
    private boolean runSuite(File jarFile, Suite s) throws IOException, ClassNotFoundException
    {
	    if (jarFile.isFile()) {
	        URL url = jarFile.toURI().toURL();
	        URL[] urls = new URL[] { url };
	        URLClassLoader cl = new URLClassLoader(urls);
	        try
	        {
	            return runSuite(cl, s);
	        }
	        finally
	        {
	            cl.close();
	        }
	    } else {
	        return false;
	    }
	
    }
    private boolean runSuite(ClassLoader classLoader, String class_name)
	        throws ClassNotFoundException {
	    //Don't confuse : XmlSuite here, is the standard testNg class. our bean class is Suite
	    XmlSuite suite = new XmlSuite();
	    suite.setName(class_name);

	    //for (com.distrimind.util.export.Suite.Test t : s.getTestCases()) 
	    {
	        XmlTest test = new XmlTest(suite);
	        test.setName(class_name);
	        List<XmlClass> classes = new ArrayList<XmlClass>();
	        //for (TestClass tc : t.getClasses()) 
	        {
	            Class<?> cls =  classLoader.loadClass(class_name);
	            if (cls != null) {
	                XmlClass xClass = new XmlClass(cls, false);
	                classes.add(xClass);
	                test.setXmlClasses(classes);
	            }
	        }
	    }
	    List<XmlSuite> suites = new ArrayList<XmlSuite>();

	    suites.add(suite);
	    TestNG tng = new TestNG();

	    tng.setXmlSuites(suites);
	    tng.run();
	    return tng.getStatus()==0;
	}
    
    private boolean runSuite(ClassLoader classLoader, Suite s)
	        throws ClassNotFoundException {
	    //Don't confuse : XmlSuite here, is the standard testNg class. our bean class is Suite
	    XmlSuite suite = new XmlSuite();
	    suite.setName(s.getName());
	    for (com.distrimind.util.export.Suite.Test t : s.getTestCases()) 
	    {
	        XmlTest test = new XmlTest(suite);
	        test.setName(t.getName());
	        
	        List<XmlClass> classes = new ArrayList<XmlClass>();
	        for (TestClass tc : t.getClasses()) {
	            Class<?> cls =  classLoader.loadClass(tc.getName());
	            
	            if (cls != null) {
	                XmlClass xClass = new XmlClass(cls, false);
	                classes.add(xClass);
	                test.setXmlClasses(classes);
	            }
	        }
	    }
	    List<XmlSuite> suites = new ArrayList<XmlSuite>();

	    suites.add(suite);
	    TestNG tng = new TestNG();

	    tng.setXmlSuites(suites);
	    tng.run();
	    return tng.getStatus()==0;
	}
}

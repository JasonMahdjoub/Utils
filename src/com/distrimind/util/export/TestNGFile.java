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
	    tng.setVerbose(5);
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
	    tng.setVerbose(5);
	    tng.setXmlSuites(suites);
	    
	    tng.run();
	    return tng.getStatus()==0;
	}
}

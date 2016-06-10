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

import java.util.ArrayList;
import java.util.List;

import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlElementWrapper;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement(name = "suite")
public class Suite {

    @XmlRootElement(name = "class")
    public static class TestClass
    {
	private String name;

	@XmlAttribute
	public String getName()
	{
	    return name;
	}

	public void setName(String _name)
	{
	    name = _name;
	}
	
    }
    
    @XmlRootElement(name = "test")
    public static class Test
    {
	private String name;
	private List<TestClass> classes;
	
	@XmlElementWrapper(name = "classes")
	@XmlElement(name = "class")
	public List<TestClass> getClasses()
	{
	    return classes;
	}

	public void setClasses(List<TestClass> _classes)
	{
	    classes = _classes;
	}

	@XmlAttribute
	public String getName()
	{
	    return name;
	}

	public void setName(String _name)
	{
	    name = _name;
	}
	
	
    }
    
    
    private String name;
    private String verbose = "1";
    private boolean parallel =false;

    private List<Test> testCases = new ArrayList<Test>();

    
    
    @XmlAttribute
    public String getName() {
	return name;
    }


    public void setName(String name) {
	this.name = name;
    }

    @XmlAttribute
    public String getVerbose() {
	return verbose;
    }


    public void setVerbose(String verbose) {
	this.verbose = verbose;
    }

    @XmlAttribute
    public boolean isParallel() {
	return parallel;
    }


    public void setParallel(boolean parallel) {
	this.parallel = parallel;
    }

    @XmlElement(name = "test")
    public List<Test> getTestCases() {
	return testCases;
    }

    public void setTestCases(List<Test> testCases) {
	this.testCases = testCases;
    }
    
    
    
}
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
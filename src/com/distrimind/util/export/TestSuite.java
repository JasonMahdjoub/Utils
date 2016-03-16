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

import org.w3c.dom.Document;
import org.w3c.dom.Node;

import com.distrimind.util.properties.XMLProperties;

/**
 * 
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 1.6
 */
public class TestSuite extends XMLProperties
{
    /**
     * 
     */
    private static final long serialVersionUID = 1616643302394705410L;

    private ArrayList<AbstractUnitTests> tests=new ArrayList<>();

    
    public TestSuite(AbstractUnitTests...tests)
    {
	super(null);

	for (AbstractUnitTests t : tests)
	    addUnitTest(t);
    }

    public void addUnitTest(AbstractUnitTests test)
    {
	tests.add(test);
    }
    

    
    public boolean executeTestsFromSystemClassLoader() throws Exception
    {
	for (AbstractUnitTests a : tests)
	{
	    if (!a.executeTestsFromSystemClassLoader())
		return false;
	}
	return true;
    }

    public static void main(String args[]) throws Exception
    {
	TestSuite suite=new TestSuite();
	suite.load(TestSuite.class.getResourceAsStream("TestSuite.xml"));
	
	if (!suite.executeTestsFromSystemClassLoader())
	{
	    System.out.print("Test suite FAILED");
	    System.exit(-1);
	}
	else
	{
	    System.out.print("Test suite has SUCCEEDED");
	    System.exit(0);
	}
	
    }
    
	@Override
	public Node getRootNode(Document _document)
	{
	    for (int i=0;i<_document.getChildNodes().getLength();i++)
	    {
		Node n=_document.getChildNodes().item(i);
		if (n.getNodeName().equals(RootNodeName))
		    return n;
	    }
	    return null;
	}

	@Override
	public Node createOrGetRootNode(Document _document)
	{
	    Node res=getRootNode(_document);
	    if (res==null)
	    {
		res=_document.createElement(RootNodeName);
		_document.appendChild(res);
	    }
	    return res;
	}
    
	private static final String RootNodeName="TestSuite";
    
}

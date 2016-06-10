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

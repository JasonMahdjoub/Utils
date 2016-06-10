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


package com.distrimind.util.properties;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.Serializable;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Modifier;
import java.lang.reflect.ParameterizedType;
import java.net.URI;
import java.net.URL;
import java.sql.Date;
import java.util.AbstractSequentialList;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Properties;
import java.util.logging.Level;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.DOMException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;



/**
 * This interface enable to partially serialize/deserialize classes that implements the current interface, in order to produce an XML file.
 * The managed types are all the primitive types, {@link String} class, {@link Date} class, {@link Class} class, {@link Level} class, {@link Map} class, {@link List} class, {@link URI} class, {@link URL} class, {@link File} class, and all classes that implements this interface.
 * 
 * Arrays are not already managed.
 * 
 * All types that are not managed are just not treated into the XML generation.
 * 
 * 
 * 
 * @author Jason Mahdjoub
 * @version 1.1
 * @since Utils 1.0
 *
 */
public abstract class XMLProperties implements Cloneable, Serializable
{

    /**
     * 
     */
    private static final long serialVersionUID = 6821595638425166680L;

    static DefaultXMLObjectParser default_xml_object_parser_instance=new DefaultXMLObjectParser();
    AbstractXMLObjectParser optional_xml_object_parser_instance;
    private Properties freeStringProperties=null;
    
    protected XMLProperties(AbstractXMLObjectParser _optional_xml_object_parser_instance)
    {
	optional_xml_object_parser_instance=_optional_xml_object_parser_instance;
    }
    
    
    /**
     * 
     * @return properties that are not managed by any class field stored into the current instance. 
     */
    public Properties getFreeStringProperties()
    {
	if (freeStringProperties==null)
	    freeStringProperties=new Properties();
	return freeStringProperties;
    }
    
    /**
     * Load properties from an XML file
     * @param xml_file the file to load
     * @throws XMLPropertiesParseException if a problem parsing occurs
     * @throws IOException of a IO problem occurs
     */
    public void load(File xml_file) throws XMLPropertiesParseException, IOException
    {
	try
	{
	    Document d=getDOM(xml_file);	
	    load(d);
	}
	catch(SAXException | ParserConfigurationException e)
	{
	    throw new XMLPropertiesParseException(e, "Impossible to read the XML file "+xml_file);
	}
    }

    /**
     * Load properties from an XML input stream
     * @param is the input stream
     * @throws XMLPropertiesParseException if a problem parsing occurs
     * @throws IOException of a IO problem occurs
     */
    public void load(InputStream is) throws XMLPropertiesParseException, IOException
    {
	try
	{
	    if (is==null)
		throw new NullPointerException("is");
	    Document d=getDOM(is);	
	    load(d);
	}
	catch(SAXException | ParserConfigurationException e)
	{
	    throw new XMLPropertiesParseException(e, "Impossible to read the given input stream !");
	}
    }
    
    
    /**
     * return the DOM from an xml file.
     * 
     * @param xmlFile the file to load
     * @return the DOM from an xml file or <code>null</code> if not found or invalid
     * @throws SAXException if a problem of XML parse/load occurs
     * @throws IOException of a IO problem occurs
     * @throws ParserConfigurationException if a problem of XML parse occurs
     */
    public static Document getDOM(File xmlFile) throws SAXException,IOException,ParserConfigurationException{
	try (final InputStream is = new FileInputStream(xmlFile)) {
	    return getDOM(is);
	}
    }
    
    /**
     * return the DOM from an xml file.
     * 
     * @param stream the stream to read
     * @return the DOM from an xml file or <code>null</code> if not found or invalid
     * @throws SAXException if a problem of XML parse/load occurs
     * @throws IOException of a IO problem occurs
     * @throws ParserConfigurationException if a problem of XML parse occurs
     */
    public static Document getDOM(InputStream stream) throws SAXException,IOException,ParserConfigurationException{
	try
	{
	    return DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(stream);
	} catch (SAXException | IOException | ParserConfigurationException e) {
	throw e;
	}
    }
     
    

    /**
     * Load properties from an XML document
     * @param document the document to load
     * @throws XMLPropertiesParseException if a problem of XML parse occurs
     */
    public void load(Document document) throws XMLPropertiesParseException
    {
	if (document==null)
	    throw new NullPointerException("document");
	
	Node n=getRootNode(document);
	if (n==null || n.getChildNodes()==null)
	    throw new XMLPropertiesParseException("Impossible to find the node named "+this.getClass().getCanonicalName());

	NodeList nl=null;
	
	for (int i=0;i<n.getChildNodes().getLength();i++)
	{
	    Node sn=n.getChildNodes().item(i);
	    if (sn!=null && sn.getNodeName().equals(this.getClass().getCanonicalName()))
	    {
		nl=sn.getChildNodes();
		break;
	    }
	}
	if (nl==null)
	    throw new XMLPropertiesParseException("Impossible to find the node named "+this.getClass().getCanonicalName());
	/*else if (nl.getLength()>1)
	    throw new XMLPropertiesParseException("The node named "+this.getClass().getCanonicalName()+" must be defined only one time");*/
	read(document, nl);
    }
    
    
    /**
     * 
     * @param _document the document
     * @return the root document node, or null if this node does not exists
     */
    public Node getRootNode(Document _document)
    {
	for (int i=0;i<_document.getChildNodes().getLength();i++)
	{
	    Node n=_document.getChildNodes().item(i);
	    if (n.getNodeName().equals(this.getClass().getName()))
		return n;
	}
	return null;
    }
	

    /**
     * Create and get root node 
     * @param _document the document
     * @return the root node
     */
    public Node createOrGetRootNode(Document _document)
    {
	Node res=getRootNode(_document);
	if (res==null)
	{
	    res=_document.createElement(this.getClass().getName());
	    _document.appendChild(res);
	}
	return res;
    }
    
    void read(Document document, NodeList node_list) throws XMLPropertiesParseException
    {
	for (int i=0;i<node_list.getLength();i++)
	{
	    Node node=node_list.item(i);
	    String node_name=node.getNodeName();
	    Class<?> c=this.getClass();
	    boolean found=false;
	    while (c!=Object.class && !found)
	    {
		for (Field f : c.getDeclaredFields())
		{
		    if (f.getName().equals(node_name) && isValid(f))
		    {
			f.setAccessible(true);
			readField(document, f, node);
			found=true;
			break;
		    }
		}
		c=c.getSuperclass();
	    }
	}
    }
    
    boolean isValid(Field field)
    {
	int mod=field.getModifiers();
	if (Modifier.isFinal(mod) || Modifier.isTransient(mod) || Modifier.isNative(mod) || Modifier.isStatic(mod))
	    return false;
	return XMLProperties.class.isAssignableFrom(field.getType())
		|| Map.class.isAssignableFrom(field.getType())
		|| List.class.isAssignableFrom(field.getType())
		|| default_xml_object_parser_instance.isValid(field.getType()) 
		|| (optional_xml_object_parser_instance!=null && optional_xml_object_parser_instance.isValid(field.getType()));
    }
    
    String getElementValue(Document document, Node node) throws XMLPropertiesParseException
    {
	    String nodeValue=node.getTextContent();
	    if (nodeValue==null)
		return null;
	    final String subpatternstring="\\w+"; 
	    
	    
	    final Pattern p=Pattern.compile("@\\{node[vV]alue/"+subpatternstring+"\\}");
	    Matcher m=p.matcher(nodeValue);
	    
	    StringBuffer res=new StringBuffer();
	    int previous_index=0;
	    
	    while (m.find())
	    {
		res.append(nodeValue.substring(previous_index, m.start()));
		previous_index=m.end();
		String group=m.group();
		String id=group.substring(12, group.length()-1);
		NodeList nl=document.getElementsByTagName(id);
		
		if (nl.getLength()==1)
		{
		    Node e=nl.item(0);
		    String value=getElementValue(document, e);
		    res.append(value);
		}
		else if (nl.getLength()==0)
		    throw new XMLPropertiesParseException("The element tagged by "+id+" was not found.");
		else 
		    throw new XMLPropertiesParseException("The element tagged by "+id+" was found in more than one occurences.");
	    }
	    res.append(nodeValue.substring(previous_index, nodeValue.length()));
	    return res.toString();
    }
    
    
    
    Object getValue(Document document, String field_name, Class<?> field_type, Node n) throws XMLPropertiesParseException
    {
	try
	{
	    
	    String nodeValue=getElementValue(document, n);
	    
	    if (nodeValue==null)
		return null;
	    if (XMLProperties.class.isAssignableFrom(field_type))
	    {
		Constructor<?> default_constructor=null;
		for (Constructor<?> c : field_type.getDeclaredConstructors())
		{
		    
		    if (c.getParameterTypes().length==0)
		    {
			default_constructor=c;
			default_constructor.setAccessible(true);
			break;
		    }
		}
		if (default_constructor==null)
		{
		    throw new XMLPropertiesParseException("The class "+field_type.getCanonicalName()+" must have a default constructor ");
		}
		
		XMLProperties e=(XMLProperties)default_constructor.newInstance();
		if (e.optional_xml_object_parser_instance==null)
		    e.optional_xml_object_parser_instance=optional_xml_object_parser_instance;
		e.read(document, n.getChildNodes());
		return e;
	    }
	    else return getValue(field_type, nodeValue);
	}
	catch (Exception e)
	{
	    throw new XMLPropertiesParseException(e, "Impossible to read the field "+field_name+" of the type "+field_type.getName());
	}	
    }
    
    Object getValue(Class<?> field_type, String nodeValue) throws Exception 
    {
	Object res=null;
	if (optional_xml_object_parser_instance!=null)
	{
	    res=optional_xml_object_parser_instance.convertXMLToObject(field_type, nodeValue);
	    if (res==Void.TYPE)
		res=default_xml_object_parser_instance.convertXMLToObject(field_type, nodeValue);
	}
	else
	    res=default_xml_object_parser_instance.convertXMLToObject(field_type, nodeValue);
	return res;
    }
    
    
    

    void readField(Document document, Field field, Node node) throws XMLPropertiesParseException
    {
	Class<?> type=field.getType();
	if (Map.class.isAssignableFrom(type))
	{
   
	    //deal with map
	    
	    try
	    {
		Map<Object, Object> m=null;
		if (Modifier.isAbstract(type.getModifiers()))
		{
		    m=new HashMap<Object, Object>();
		}
		else
		{
		    @SuppressWarnings("unchecked")
		    Map<Object, Object> newInstance = (Map<Object, Object>)type.newInstance();
		    m=newInstance;
		}
		
		/*Class<?> key_map_class= (Class<?>) ((ParameterizedType) field.getGenericType()).getActualTypeArguments()[0];
		Class<?> value_map_class= (Class<?>) ((ParameterizedType) field.getGenericType()).getActualTypeArguments()[1];*/
		
	        NodeList node_list=node.getChildNodes();
	        for (int i=0;i<node_list.getLength();i++)
	        {
	            Node n=node_list.item(i);
	            if (n.getNodeName().equals("ElementMap"))
	            {
	        	Node keyn=null;
	        	Node valuen=null;
	        	NodeList ne=n.getChildNodes();
	        	
	        	for (int j=0;j<ne.getLength() && !(keyn!=null && valuen!=null);j++)
	        	{
	        	    Node n2=ne.item(j);
	        	    
	        	    if (n2.getNodeName().equals("key"))
	        		keyn=n2;
	        	    else if (n2.getNodeName().equals("value"))
	        		valuen=n2;
	        	}
	        	
	        	if (keyn!=null && valuen!=null)
	        	{
	        	    Class<?> key_map_class= Class.forName(keyn.getAttributes().getNamedItem("ElementType").getNodeValue());
	        	    Class<?> value_map_class= Class.forName(valuen.getAttributes().getNamedItem("ElementType").getNodeValue());
	        	    
	        	    Object okey=getValue(document, field.getName(), key_map_class, keyn);
	        	    Object ovalue=getValue(document, field.getName(), value_map_class, valuen);

	        	    
	        	    if (!(okey!=null && okey==Void.TYPE) && !(ovalue!=null && ovalue==Void.TYPE))
	        	    {
	        		m.put(okey, ovalue);
	        	    }
	        	}
	            }	            
	        }
	        field.set(this, m);
	        
	    }
	    catch (InstantiationException | IllegalAccessException | DOMException | ClassNotFoundException e)
	    {
		throw new XMLPropertiesParseException(e, "Impossible to read the type "+type.getName());
	    }
	    
	}
	else if (List.class.isAssignableFrom(type) /*|| type.isArray()*/) //TODO add array management
	{
	    //deal with list
	    
	    try
	    {
		List<Object> l=null;
		{
		    if (type.isArray())
		    {
			l=new ArrayList<>();
		    }
		    else
		    {
			
			if (Modifier.isAbstract(type.getModifiers()))
			{
			    if (AbstractSequentialList.class.isAssignableFrom(type))
				l = new LinkedList<>();
			    else
				l = new ArrayList<>();
			}
			else
			{
			    @SuppressWarnings("unchecked")
			    List<Object> newInstance = (List<Object>)type.newInstance();
			    l=newInstance;
			}
		    }
		}
		
	        //Class<?> element_list_class= (Class<?>) ((ParameterizedType) field.getGenericType()).getActualTypeArguments()[0];
	        NodeList node_list=node.getChildNodes();
	        for (int i=0;i<node_list.getLength();i++)
	        {
	            Node n=node_list.item(i);
	            if (n.getNodeName().equals("ElementList"))
	            {
	        	Class<?> element_list_class= Class.forName(n.getAttributes().getNamedItem("ElementType").getNodeValue());	        	
	        	Object o=getValue(document, field.getName(), element_list_class, n);
	        	if (!(o!=null && o==Void.TYPE))
	        	    l.add(o);
	            }
	        }
	        if (type.isArray())
	        {
	            field.set(this, l.toArray());
	        }
	        else
	        {
	            field.set(this, l);
	        }
	        
	    }
	    catch (InstantiationException | IllegalAccessException | DOMException | ClassNotFoundException e)
	    {
		throw new XMLPropertiesParseException(e, "Impossible to read the type "+type.getName());
	    }
	    
	    
    
	}
	else if (XMLProperties.class.isAssignableFrom(type))
	{
	    //deal with Properties instance
	    
	    try
	    {
		XMLProperties p = (XMLProperties)field.get(this);
		if (p==null)
		{
			Constructor<?> default_constructor=null;
			for (Constructor<?> c : type.getDeclaredConstructors())
			{
			    
			    if (c.getParameterTypes().length==0)
			    {
				default_constructor=c;
				default_constructor.setAccessible(true);
				break;
			    }
			}
			if (default_constructor==null)
			{
			    throw new XMLPropertiesParseException("The class "+type.getCanonicalName()+" must have a default constructor ");
			}
		    
		    p=(XMLProperties)default_constructor.newInstance();
		    field.set(this, p);
		}
		if (p.optional_xml_object_parser_instance==null)
		    p.optional_xml_object_parser_instance=optional_xml_object_parser_instance;
		p.read(document, node.getChildNodes());
	    }
	    catch (InstantiationException | IllegalAccessException | IllegalArgumentException | InvocationTargetException e)
	    {
		throw new XMLPropertiesParseException(e, "Impossible to read the type "+type.getName());
	    }
	}
	else if (type.isPrimitive())
	{
   
	    //deal with primitive type
	    try
	    {
		String nodeValue=node.getTextContent();
		if (nodeValue==null)
		    return; 
		if (type==boolean.class)
		{
		    field.setBoolean(this, Boolean.parseBoolean(nodeValue));
		}
		else if (type==byte.class)
		{
		    field.setByte(this, Byte.parseByte(nodeValue));
		}
		else if (type==short.class)
		{
		    field.setShort(this, Short.parseShort(nodeValue));
		}
		else if (type==int.class)
		{
		    field.setInt(this, Integer.parseInt(nodeValue));
		}
		else if (type==long.class)
		{
		    field.setLong(this, Long.parseLong(nodeValue));
		}
		else if (type==float.class)
		{
		    field.setFloat(this, Float.parseFloat(nodeValue));
		}
		else if (type==double.class)
		{
		    field.setDouble(this, Double.parseDouble(nodeValue));
		}
		else if (type==char.class)
		{
		    field.setChar(this, nodeValue.charAt(0));
		}
		else
		    throw new XMLPropertiesParseException("Unknow primitive type "+type.getName());
		    
	    }
	    catch(IllegalArgumentException | IllegalAccessException e)
	    {
		throw new XMLPropertiesParseException(e, "Impossible read the field "+field.getName());
	    }
	}
	else 
	{
	    try
	    {
		Object o=getValue(document, field.getName(), type, node);
		if (!(o!=null && o==Void.TYPE))
		    field.set(this, o);
	    }
	    catch(IllegalArgumentException | IllegalAccessException | DOMException e)
	    {
		throw new XMLPropertiesParseException(e, "Impossible read the field "+field.getName());
	    }

	    
	}
    }

    
    /**
     * Save properties into an XML file
     * @param xml_file the file to save
     * @throws XMLPropertiesParseException if a problem of XML parse occurs
     */
    public void save(File xml_file) throws XMLPropertiesParseException
    {
	try
	{
	    DocumentBuilderFactory docFactory = DocumentBuilderFactory.newInstance();
	    DocumentBuilder docBuilder = docFactory.newDocumentBuilder();

	    // root elements
	    Document doc = docBuilder.newDocument();
	    doc.setXmlStandalone(true);
	    save(doc);
	
	    TransformerFactory transformerFactory = TransformerFactory.newInstance();
	    Transformer transformer = transformerFactory.newTransformer();
	    DOMSource source = new DOMSource(doc);
	    StreamResult result = new StreamResult(xml_file);
	    transformer.setOutputProperty(OutputKeys.METHOD, "xml");
	    transformer.setOutputProperty(OutputKeys.INDENT, "yes");
	    transformer.setOutputProperty(OutputKeys.STANDALONE, "yes");
	    transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "4");
	    transformer.transform(source, result);
	}
	catch(ParserConfigurationException | TransformerException e)
	{
	    throw new XMLPropertiesParseException(e, "");
	}
    }
    
    /**
     * Save properties into an XML document
     * @param doc the document
     * @throws XMLPropertiesParseException if a problem of XML parse occurs
     */
    public void save(Document doc) throws XMLPropertiesParseException
    {
	try
	{
	    Node root=doc.createElement(this.getClass().getCanonicalName());
	    if (write(doc, root))
		createOrGetRootNode(doc).appendChild(root);
	}
	catch(DOMException e)
	{
	    throw new XMLPropertiesParseException(e, "");
	}
    }
    
    boolean write(Document document, Node element) throws XMLPropertiesParseException
    {
	Class<?> c=this.getClass();
	while (c!=Object.class)
	{
	    for (Field f : c.getDeclaredFields())
	    {
		if (isValid(f))
		{
		    f.setAccessible(true);
		    writeField(document, element, f);
		}
	    }
	    c=c.getSuperclass();
	}
	return true;
    }
    
    void writeField(Document document, Node parent_element, Field field) throws XMLPropertiesParseException
    {
	Class<?> type=field.getType();
	if (optional_xml_object_parser_instance!=null && optional_xml_object_parser_instance.isValid(type))
	{
	    try
	    {
		Element element=document.createElement(field.getName());
		if (setTextContent(document, element, field.getName(), field.getType(), field.get(this)))
		    parent_element.appendChild(element);
	    }
	    catch(IllegalArgumentException | IllegalAccessException | DOMException e)
	    {
		throw new XMLPropertiesParseException(e, "Impossible read the field "+field.getName());
	    }
	}
	else if (Map.class.isAssignableFrom(type))
	{
	    
	    //deal with map
	    
	    
	    try
	    {
		
		@SuppressWarnings("unchecked")
		Map<Object, Object> m=(Map<Object, Object>) field.get(this);
		if (m==null)
		    return;
		Element element=document.createElement(field.getName());
		
		Iterator<Map.Entry<Object, Object>> it=m.entrySet().iterator();
		while (it.hasNext())
		{
		    Map.Entry<Object, Object> entry=it.next();
		    Element elementM = document.createElement("ElementMap");
		    Element key=document.createElement("key");
	            /*Attr attr_key=document.createAttribute("type");
	            attr_key.setValue(key_map_class.getCanonicalName());
	            key.setAttributeNode(attr_key);*/
		    elementM.appendChild(key);
		    Object k=entry.getKey();
		    if (setTextContent(document, key, field.getName(), k==null?null:k.getClass(), k))
		    {
			key.setAttribute("ElementType", k==null?null:k.getClass().getCanonicalName());
			Element value=document.createElement("value");
		        /*Attr attr_value=document.createAttribute("type");
		        attr_value.setValue(value_map_class.getCanonicalName());
		        key.setAttributeNode(attr_value);*/

			elementM.appendChild(value);
			Object v=entry.getValue();
			if (setTextContent(document, value, field.getName(), v==null?null:v.getClass(), v))
			{
			    value.setAttribute("ElementType", v==null?null:v.getClass().getCanonicalName());
			    element.appendChild(elementM);
			}
		    }
		}
		parent_element.appendChild(element);
	    }
	    catch (IllegalAccessException | DOMException e)
	    {
		throw new XMLPropertiesParseException(e, "Impossible to read the type "+type.getName());
	    }
	    
	}
	else if (List.class.isAssignableFrom(type))
	{
	    //deal with list
	    
	    try
	    {
		@SuppressWarnings("unchecked")
		List<Object> l=(List<Object>) field.get(this);
		if (l==null)
		    return;

	        Class<?> element_list_class= (Class<?>) ((ParameterizedType) field.getGenericType()).getActualTypeArguments()[0];
	        
	        Element element=document.createElement(field.getName());
	        
	        for (Object o : l)
	        {
	            Element elemL=document.createElement("ElementList");
	            
	            /*Attr attr=document.createAttribute("type");
	            attr.setValue(o.getClass().getCanonicalName());
	            elemL.setAttributeNode(attr);*/
	            if (setTextContent(document, elemL, field.getName(), o==null?element_list_class:o.getClass(), o))
	            {
	        	elemL.setAttribute("ElementType", o==null?element_list_class.getCanonicalName():o.getClass().getCanonicalName());
	        	element.appendChild(elemL);
	            }
	        }
	        parent_element.appendChild(element);
	    }
	    catch (IllegalAccessException | DOMException e)
	    {
		throw new XMLPropertiesParseException(e, "Impossible to read the type "+type.getName());
	    }
   	}//TODO add array management
	/*else if (type.isArray())
	{
	    //deal with array
	    
	    try
	    {
		Object l[]=(Object[]) field.get(this);

	        Class<?> element_list_class= (Class<?>) ((ParameterizedType) field.getGenericType()).getActualTypeArguments()[0];
	        
	        Element element=document.createElement(field.getName());
	        
	        for (Object o : l)
	        {
	            Element elemL=document.createElement("ElementList");
	            if (setTextContent(document, elemL, field.getName(), element_list_class, o))
	            {
	        	element.appendChild(elemL);
	            }
	        }
	        parent_element.appendChild(element);
	    }
	    catch (IllegalAccessException | DOMException e)
	    {
		throw new XMLPropertiesParseException(e, "Impossible to read the type "+type.getName());
	    }
	    
	}*/
	else if (XMLProperties.class.isAssignableFrom(type))
	{
	    //deal with Properties instance
	    
	    try
	    {
		XMLProperties p = (XMLProperties)field.get(this);
		if (p!=null)
		{
		    if (p.optional_xml_object_parser_instance==null)
			p.optional_xml_object_parser_instance=optional_xml_object_parser_instance;
		    Element element=document.createElement(field.getName());
		    if (p.write(document, element))
			parent_element.appendChild(element);
		}
	    }
	    catch (IllegalAccessException e)
	    {
		throw new XMLPropertiesParseException(e, "Impossible to read the type "+type.getName());
	    }
	}
	else if (type.isPrimitive())
	{
	    
	    //deal with primitive type
	    try
	    {
		Element element=document.createElement(field.getName());
		
		if (type==boolean.class)
		{
		    element.setTextContent(Boolean.toString(field.getBoolean(this)));
		}
		else if (type==byte.class)
		{
		    element.setTextContent(Byte.toString(field.getByte(this)));
		}
		else if (type==short.class)
		{
		    element.setTextContent(Short.toString(field.getShort(this)));
		}
		else if (type==int.class)
		{
		    element.setTextContent(Integer.toString(field.getInt(this)));
		}
		else if (type==long.class)
		{
		    element.setTextContent(Long.toString(field.getLong(this)));
		}
		else if (type==float.class)
		{
		    element.setTextContent(Float.toString(field.getFloat(this)));
		}
		else if (type==double.class)
		{
		    element.setTextContent(Double.toString(field.getDouble(this)));
		}
		else if (type==char.class)
		{
		    element.setTextContent(Character.toString(field.getChar(this)));
		}
		else
		    return;
		parent_element.appendChild(element);
		    
	    }
	    catch(IllegalArgumentException | IllegalAccessException e)
	    {
		throw new XMLPropertiesParseException(e, "Impossible read the field "+field.getName());
	    }
	}
	else 
	{
	    try
	    {
		Element element=document.createElement(field.getName());
		if (setTextContent(document, element, field.getName(), field.getType(), field.get(this)))
		    parent_element.appendChild(element);
	    }
	    catch(IllegalArgumentException | IllegalAccessException | DOMException e)
	    {
		throw new XMLPropertiesParseException(e, "Impossible read the field "+field.getName());
	    }

	    
	}	
    }
    
    
    String getString(Class<?> field_type, Object object) throws Exception
    {
	String res=null;
	if (optional_xml_object_parser_instance!=null)
	{
	    res=optional_xml_object_parser_instance.convertObjectToXML(field_type, object);
	    if (res==null)
		res=default_xml_object_parser_instance.convertObjectToXML(field_type, object);
	}
	else
	    res=default_xml_object_parser_instance.convertObjectToXML(field_type, object);
	return res;
    }
    
    boolean setTextContent(Document document, Node node, String field_name, Class<?> field_type, Object object) throws XMLPropertiesParseException
    {
	try
	{
	    if (object==null)
	    {
		node.setTextContent(null);
		return false;
	    }
	    else if (XMLProperties.class.isAssignableFrom(field_type))
	    {
		XMLProperties e=(XMLProperties)object;
		if (e.optional_xml_object_parser_instance==null)
		    e.optional_xml_object_parser_instance=optional_xml_object_parser_instance;
		return e.write(document, node);
	    }
	    else
	    {
		String res=getString(field_type, object);
		if (res==null)
		{
		    return false;
		}
		else
		{
		    node.setTextContent(res);
		    return true;
		}
	    }
	}
	catch (Exception e)
	{
	    throw new XMLPropertiesParseException(e, "Impossible to write the field "+field_name+" of the type "+field_type.getName());
	}	
    }
    
    
    /**
     * Load properties from {@link Properties} class.
     * 
     * 
     * if one property does not exists, put the value into the free string properties returned by {@link #getFreeStringProperties()}.
     * 
     * @param properties the properties
     * @throws IllegalArgumentException if a problem of parse occurs
     */
    public void loadFromProperties(Properties properties) throws IllegalArgumentException
    {
	for (Entry<Object, Object> e : properties.entrySet())
	{
		String key=(String)e.getKey();
		String value=(String)e.getValue();
		
		if (!XMLProperties.this.setField(XMLProperties.this, key.split("\\."), 0, value))
		{
		    getFreeStringProperties().put(key, value);
		}
	}
    }

    
    boolean setField(XMLProperties instance, String keys[], int current_index, String value) throws IllegalArgumentException
    {
	try
	{
        	if (instance==null)
        	    return false;
        	Class<?> c=instance.getClass();
        	while (c!=Object.class)
        	{
        	    for (Field f : c.getDeclaredFields())
        	    {
        		if (f.getName().equals(keys[current_index]) && isValid(f))
        		{
        		    f.setAccessible(true);
        		    if (current_index==keys.length-1)
        		    {
        			instance.setField(f, value);
        			return true;
        		    }
        		    else
        		    {
        			if (XMLProperties.class.isAssignableFrom(f.getType()))
        			{
        			    boolean toreload=false;
        			    XMLProperties i=(XMLProperties)f.get(instance);
        			    if (i==null)
        			    {
        				toreload=true;
        				Constructor<?> construct=f.getType().getDeclaredConstructor();
        				construct.setAccessible(true);
        				i=(XMLProperties) construct.newInstance();
        			    }
        			    
        			    boolean ok=setField(i, keys, current_index+1, value);
        			    if (ok && toreload)
        				f.set(instance, i);
        			    return ok;
        			}
        			else 
        			    return false;
        		    }
        		    
        		}
        	    }
        	    c=c.getSuperclass();
        	}
        	return false;
	}
	catch(IllegalAccessException | InstantiationException | NoSuchMethodException | SecurityException | InvocationTargetException e)
	{
	    throw new IllegalArgumentException(e);
	}
    }
    
    @SuppressWarnings("unchecked")
    void setField(Field field, String value) throws IllegalArgumentException
    {
	try
	{
	    Class<?> field_type=field.getType();
	    if (field_type.isPrimitive())
	    {
		if (value==null)
		    return;
		else
		{
		    if (field_type==boolean.class)
		    {
			field.setBoolean(this, Boolean.parseBoolean(value));
		    }
		    else if (field_type==byte.class)
		    {
			field.setByte(this, Byte.parseByte(value));
		    }
		    else if (field_type==short.class)
		    {
			field.setShort(this, Short.parseShort(value));
		    }
		    else if (field_type==int.class)
		    {
			field.setInt(this, Integer.parseInt(value));
		    }
		    else if (field_type==long.class)
		    {
			field.setLong(this, Long.parseLong(value));
		    }
		    else if (field_type==float.class)
		    {
			field.setFloat(this, Float.parseFloat(value));
		    }
		    else if (field_type==double.class)
		    {
			field.setDouble(this, Double.parseDouble(value));
		    }
		    else if (field_type==char.class)
		    {
			field.setChar(this, value.charAt(0));
		    }
		    else
			return;	
		    
		}
	    }
	    else if (List.class.isAssignableFrom(field_type))
	    {
		if (value==null || value.equals("null"))
		    field.set(this, null);
		else
		{
		    
		    Class<?> element_list_class= (Class<?>) ((ParameterizedType) field.getGenericType()).getActualTypeArguments()[0];
		    List<Object> l=null;
		    
		    if (Modifier.isAbstract(field_type.getModifiers()))
			l=new ArrayList<>();
		    else
			l=(List<Object>)field_type.newInstance();
		    
		    
		    if (value.startsWith("{") && value.endsWith("}"))
		    {
			value=value.substring(1, value.length()-1);
			for (String v : value.split(";"))
			{
			    Object o=getValue(element_list_class, v);
			    if (o!=null && o!=Void.TYPE)
				l.add(o);
			}
		    
			field.set(this, l);
		    }
		}
		    
		
	    }
	    else if (Map.class.isAssignableFrom(field_type))
	    {
		
		Map<Object, Object> m=null;
		if (!value.equals("null"))
		{
		    if (Modifier.isAbstract(field_type.getModifiers()))
		    {
			m=new HashMap<Object, Object>();
		    }
		    else
		    {
			Map<Object, Object> newInstance = (Map<Object, Object>)field_type.newInstance();
			m=newInstance;
		    }

		
		    if (value.startsWith("{") && value.endsWith("}"))
		    {
			value=value.substring(1, value.length()-1);
			for (String v : value.split(";"))
			{
			    String split[]=v.split(":");
			    if (split.length==4 && !split[0].equals("null"))
			    {
				Class<?> key_map_class= (Class<?>) Class.forName(split[0]);
				Class<?> value_map_class=null;
				if (!split[2].equals("null"))
				    value_map_class= (Class<?>) Class.forName(split[2]);
			
				Object ok=getValue(key_map_class, split[1]);
				if (ok==null || ok!=Void.TYPE)
				{
				    Object ov=null;
				    if (value_map_class!=null)
					ov=getValue(value_map_class, split[3]);
				    if (ov==null || ov!=Void.TYPE)
					m.put(ok, ov);
				}
			    }
			    
			}
			
		    }
		}
		field.set(this, m);
	    }
	    else
	    {
		Object o=getValue(field_type, value);
		if (o==null || !(o==Void.TYPE))
		    field.set(this, o);
	    }
	}
	catch (Exception e)
	{
	    throw new IllegalArgumentException("Impossible to read the field "+field.getName()+" of the type "+field.getType(), e);
	}	
    }
    
    /**
     * Convert this properties to a {@link Properties} class format.
     * @return this properties converted to a {@link Properties} class format.
     */
    public Properties convertToStringProperties()
    {
	Properties res=new Properties();
	Class<?> c=this.getClass();
	while (c!=Object.class)
	{
	    for (Field f : c.getDeclaredFields())
	    {
		if (!isValid(f))
		    continue;
		f.setAccessible(true);
		
		try
		{
		    if (f.getType().isPrimitive())
		    {
			res.put(f.getName(), getPrimitiveValue(f));
		    }
		    else if (List.class.isAssignableFrom(f.getType()))
		    {
			StringBuffer buffer=new StringBuffer();
			Object o=f.get(this);
			if (o==null)
			    buffer.append("null");
			else
			{
			    Class<?> element_list_class= (Class<?>) ((ParameterizedType) f.getGenericType()).getActualTypeArguments()[0];
			    buffer.append("{");
			    List<?> l=(List<?>)o;
			    boolean first=true;
			    for (Object e : l)
			    {
				String s=null;
				
				if (e==null)
				    s="null";
				else
				{
				    s=getString(element_list_class, e);
				}
				if (s!=null)
				{
				    if (first)
					first=false;
				    else
					buffer.append(";");
				    buffer.append(s);
				}
			    }
			    buffer.append("}");
			}
			res.put(f.getName(), buffer.toString());
		    }
		    else if (Map.class.isAssignableFrom(f.getType()))
		    {
			StringBuffer buffer=new StringBuffer();
			Object o=f.get(this);
			if (o==null)
			    buffer.append("null");
			else
			{
			    buffer.append("{");
			    Map<?, ?> m=(Map<?, ?>)o;
			    boolean first=true;
			    for (Map.Entry<?, ?> e : m.entrySet())
			    {
				String ks=null,vs=null;
				
				if (e.getKey()!=null)
				    ks=getString(e.getKey().getClass(), e.getKey());
				if (e.getValue()!=null)
				    vs=getString(e.getValue().getClass(), e.getValue());

				if (ks!=null)
				{
				    if (first)
					first=false;
				    else
					buffer.append(";");
				    buffer.append(e.getKey().getClass().getCanonicalName());
				    buffer.append(":");
				    buffer.append(ks);
				    buffer.append(":");
				    if (vs==null)
					buffer.append("null");
				    else
					buffer.append(e.getValue().getClass().getCanonicalName());
				    buffer.append(":");
				    buffer.append(vs);
				}
			    }
			    buffer.append("}");
			}
			res.put(f.getName(), buffer.toString());
		    }
		    else if (XMLProperties.class.isAssignableFrom(f.getType()))
		    {
			Object o=f.get(this);
			if (o!=null)
			{
			    XMLProperties xmlp=(XMLProperties)o;
			    if (xmlp.optional_xml_object_parser_instance==null)
				xmlp.optional_xml_object_parser_instance=optional_xml_object_parser_instance;
			    for (Map.Entry<Object, Object> e : xmlp.convertToStringProperties().entrySet())
			    {
				res.put(f.getName()+"."+e.getKey(), e.getValue());
			    }
			}
		    }
		    else
		    {
			Object o=f.get(this);
			if (o!=null)
			{
			    String s=getString(f.getType(), o);
			    if (s!=null)
				res.put(f.getName(), s);
			}
		    }
		}
		catch(Exception e)
		{
		    e.printStackTrace();
		}
	    }
	    c=c.getSuperclass();
	}
	res.putAll(getFreeStringProperties());
	return res;
    }
    
    String getPrimitiveValue(Field field) throws IllegalArgumentException, IllegalAccessException
    {
	Class<?> field_type=field.getType();
	    if (field_type==boolean.class)
	    {
		return Boolean.toString(field.getBoolean(this));
	    }
	    else if (field_type==byte.class)
	    {
		return Byte.toString(field.getByte(this));
	    }
	    else if (field_type==short.class)
	    {
		return Short.toString(field.getShort(this));
	    }
	    else if (field_type==int.class)
	    {
		return Integer.toString(field.getInt(this));
	    }
	    else if (field_type==long.class)
	    {
		return Long.toString(field.getLong(this));
	    }
	    else if (field_type==float.class)
	    {
		return Float.toString(field.getFloat(this));
	    }
	    else if (field_type==double.class)
	    {
		return Double.toString(field.getDouble(this));
	    }
	    else if (field_type==char.class)
	    {
		return Character.toString(field.getChar(this));
	    }
	    else
		return null;	
	
    }
    
}

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

import com.distrimind.util.AbstractDecentralizedID;
import org.w3c.dom.*;
import org.xml.sax.SAXException;
import org.yaml.snakeyaml.DumperOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.AbstractConstruct;
import org.yaml.snakeyaml.constructor.Construct;
import org.yaml.snakeyaml.introspector.BeanAccess;
import org.yaml.snakeyaml.introspector.Property;
import org.yaml.snakeyaml.nodes.NodeTuple;
import org.yaml.snakeyaml.nodes.ScalarNode;
import org.yaml.snakeyaml.nodes.Tag;
import org.yaml.snakeyaml.representer.Represent;
import org.yaml.snakeyaml.representer.Representer;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.*;
import java.lang.reflect.*;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URL;
import java.sql.Date;
import java.util.*;
import java.util.Map.Entry;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Level;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * This interface enable to partially serialize/deserialize classes that
 * implements the current interface, in order to produce an XML file. The
 * managed types are all the primitive types, {@link String} class, {@link Date}
 * class, {@link Class} class, {@link Level} class, {@link Map} class,
 * {@link List} class, {@link URI} class, {@link URL} class, {@link File} class,
 * and all classes that implements this interface.
 * 
 * Arrays are not already managed.
 * 
 * All types that are not managed are just not treated into the XML generation.
 * 
 * 
 * 
 * @author Jason Mahdjoub
 * @version 2.0
 * @since Utils 1.0
 *
 */
public abstract class MultiFormatProperties implements Cloneable, Serializable {

	/**
	 * 
	 */
	private static final long serialVersionUID = 6821595638425166680L;

	final transient DefaultMultiFormatObjectParser default_xml_object_parser_instance = new DefaultMultiFormatObjectParser();

	/**
	 * return the DOM from an xml file.
	 * 
	 * @param xmlFile
	 *            the file to load
	 * @return the DOM from an xml file or <code>null</code> if not found or invalid
	 * @throws SAXException
	 *             if a problem of XML parse/load occurs
	 * @throws IOException
	 *             of a IO problem occurs
	 * @throws ParserConfigurationException
	 *             if a problem of XML parse occurs
	 */
	public static Document getDOM(File xmlFile) throws SAXException, IOException, ParserConfigurationException {
		try (final InputStream is = new FileInputStream(xmlFile)) {
			return getDOM(is);
		}
	}

	/**
	 * return the DOM from an xml file.
	 * 
	 * @param stream
	 *            the stream to read
	 * @return the DOM from an xml file or <code>null</code> if not found or invalid
	 * @throws SAXException
	 *             if a problem of XML parse/load occurs
	 * @throws IOException
	 *             of a IO problem occurs
	 * @throws ParserConfigurationException
	 *             if a problem of XML parse occurs
	 */
	public static Document getDOM(InputStream stream) throws SAXException, IOException, ParserConfigurationException {
		DocumentBuilderFactory dbf=DocumentBuilderFactoryWithNonDTD.newDocumentBuilderFactoryWithNonDTDInstance();

		return dbf.newDocumentBuilder().parse(stream);

	}

	transient AbstractMultiFormatObjectParser optional_xml_object_parser_instance;

	private Properties freeStringProperties = null;

	protected MultiFormatProperties(AbstractMultiFormatObjectParser _optional_xml_object_parser_instance) {
		optional_xml_object_parser_instance = _optional_xml_object_parser_instance;
	}

	private Class<?> getGenericType(Field f) throws IllegalAccessException
	{
		Class<?> element_list_class;
		Type t=((ParameterizedType) f.getGenericType()).getActualTypeArguments()[0];
		if (t instanceof Class)
			element_list_class= (Class<?>) t;
		else if (t instanceof ParameterizedType)
			element_list_class= (Class<?>) ((ParameterizedType)t).getRawType();
		else
			throw new IllegalAccessException();
		return element_list_class;
	}
    /**
     * Convert this properties to a {@link Properties} class format.
     *
     * @return this properties converted to a {@link Properties} class format.
     * @throws PropertiesParseException if a problem occurs
     */
    public Properties convertToStringProperties() throws PropertiesParseException {
        return convertToStringProperties(null);
    }
	
	/**
	 * Convert this properties to a {@link Properties} class format.
	 * @param referenceProperties the reference properties. If a property is the same between this instance and the given reference, that the properties is not saved into the file
	 * @return this properties converted to a {@link Properties} class format.
     * @throws PropertiesParseException if a problem occurs
	 */
	public Properties convertToStringProperties(MultiFormatProperties referenceProperties) throws PropertiesParseException {
		Properties res = new Properties();
		Class<?> c = this.getClass();
		while (c != Object.class) {
			for (Field f : c.getDeclaredFields()) {
				if (!isValid(f))
					continue;
				f.setAccessible(true);
                try {
                    if (canExclude(referenceProperties, f, f.get(this)))
                        continue;
                } catch (IllegalAccessException e) {
                    throw new PropertiesParseException(e, "");
                }
				try {
					if (f.getType().isPrimitive()) {
						res.put(f.getName(), getPrimitiveValue(f));
					} else if (List.class.isAssignableFrom(f.getType()) || Set.class.isAssignableFrom(f.getType())) {
						StringBuilder buffer = new StringBuilder();
						Object o = f.get(this);
						if (o == null)
							buffer.append("null");
						else {
							Class<?> element_list_class=getGenericType(f);
							
							buffer.append("{");
							Collection<?> l = (Collection<?>) o;
							boolean first = true;
							for (Object e : l) {
								String s;

								if (e == null)
									s = "null";
								else {
									s = getString(element_list_class, e);
								}
								if (s != null) {
									if (first)
										first = false;
									else
										buffer.append(";");
									buffer.append(s);
								}
							}
							buffer.append("}");
						}
						res.put(f.getName(), buffer.toString());
					}
					else if (Map.class.isAssignableFrom(f.getType())) {
						StringBuilder buffer = new StringBuilder();
						Object o = f.get(this);
						if (o == null)
							buffer.append("null");
						else {
							buffer.append("{");
							Map<?, ?> m = (Map<?, ?>) o;
							boolean first = true;
							for (Map.Entry<?, ?> e : m.entrySet()) {
								String ks = null, vs = null;

								if (e.getKey() != null)
									ks = getString(e.getKey().getClass(), e.getKey());
								if (e.getValue() != null)
									vs = getString(e.getValue().getClass(), e.getValue());

								if (ks != null) {
									if (first)
										first = false;
									else
										buffer.append(";");
									buffer.append(e.getKey().getClass().getCanonicalName());
									buffer.append(":");
									buffer.append(ks);
									buffer.append(":");
									if (vs == null)
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
					} else if (MultiFormatProperties.class.isAssignableFrom(f.getType())) {
						Object o = f.get(this);
						if (o != null) {
							MultiFormatProperties xmlp = (MultiFormatProperties) o;
							if (xmlp.optional_xml_object_parser_instance == null)
								xmlp.optional_xml_object_parser_instance = optional_xml_object_parser_instance;
							for (Map.Entry<Object, Object> e : xmlp.convertToStringProperties(referenceProperties).entrySet()) {
								res.put(o.getClass().getName() + "." + f.getName() + "." + e.getKey(), e.getValue());
							}
						}
					} else {
						Object o = f.get(this);
						if (o != null) {
							String s = getString(f.getType(), o);
							if (s != null)
								res.put(f.getName(), s);
						}
					}
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
			c = c.getSuperclass();
		}
		res.putAll(getFreeStringProperties());
		return res;
	}

	/**
	 * Create and get root node
	 * 
	 * @param _document
	 *            the document
	 * @return the root node
	 */
	public Node createOrGetRootNode(Document _document) {
		Node res = getRootNode(_document);
		if (res == null) {
			res = _document.createElement(this.getClass().getName());
			_document.appendChild(res);
		}
		return res;
	}

	String getElementValue(Document document, Node node) throws PropertiesParseException {
		String nodeValue = node.getTextContent();
		if (nodeValue == null)
			return null;
		final String subPatternString = "\\w+";

		final Pattern p = Pattern.compile("@\\{node[vV]alue/" + subPatternString + "}");
		Matcher m = p.matcher(nodeValue);

		StringBuilder res = new StringBuilder();
		int previous_index = 0;

		while (m.find()) {
			res.append(nodeValue, previous_index, m.start());
			previous_index = m.end();
			String group = m.group();
			String id = group.substring(12, group.length() - 1);
			NodeList nl = document.getElementsByTagName(id);

			if (nl.getLength() == 1) {
				Node e = nl.item(0);
				String value = getElementValue(document, e);
				res.append(value);
			} else if (nl.getLength() == 0)
				throw new PropertiesParseException("The element tagged by " + id + " was not found.");
			else
				throw new PropertiesParseException(
						"The element tagged by " + id + " was found in more than one occurrences.");
		}
		res.append(nodeValue, previous_index, nodeValue.length());
		return res.toString();
	}

	/**
	 * 
	 * @return properties that are not managed by any class field stored into the
	 *         current instance.
	 */
	public Properties getFreeStringProperties() {
		if (freeStringProperties == null)
			freeStringProperties = new Properties();
		return freeStringProperties;
	}

	String getPrimitiveValue(Field field) throws IllegalArgumentException, IllegalAccessException {
		Class<?> field_type = field.getType();
		if (field_type == boolean.class) {
			return Boolean.toString(field.getBoolean(this));
		} else if (field_type == byte.class) {
			return Byte.toString(field.getByte(this));
		} else if (field_type == short.class) {
			return Short.toString(field.getShort(this));
		} else if (field_type == int.class) {
			return Integer.toString(field.getInt(this));
		} else if (field_type == long.class) {
			return Long.toString(field.getLong(this));
		} else if (field_type == float.class) {
			return Float.toString(field.getFloat(this));
		} else if (field_type == double.class) {
			return Double.toString(field.getDouble(this));
		} else if (field_type == char.class) {
			return Character.toString(field.getChar(this));
		} else
			return null;

	}

	/**
	 * 
	 * @param _document
	 *            the document
	 * @return the root document node, or null if this node does not exists
	 */
	public Node getRootNode(Document _document) {
		for (int i = 0; i < _document.getChildNodes().getLength(); i++) {
			Node n = _document.getChildNodes().item(i);
			if (n.getNodeName().equals(this.getClass().getName()))
				return n;
		}
		return null;
	}

	String getString(Class<?> field_type, Object object) {
		String res ;
		if (optional_xml_object_parser_instance != null) {
			res = optional_xml_object_parser_instance.convertObjectToString(field_type, object);
			if (res == null)
				res = default_xml_object_parser_instance.convertObjectToString(field_type, object);
		} else
			res = default_xml_object_parser_instance.convertObjectToString(field_type, object);
		return res;
	}

	Object getValue(Class<?> field_type, String nodeValue) throws Exception {
		Object res ;
		if (optional_xml_object_parser_instance != null) {
			res = optional_xml_object_parser_instance.convertStringToObject(field_type, nodeValue);
			if (res == Void.TYPE)
				res = default_xml_object_parser_instance.convertStringToObject(field_type, nodeValue);
		} else
			res = default_xml_object_parser_instance.convertStringToObject(field_type, nodeValue);
		return res;
	}

	Object getValue(Document document, String field_name, Class<?> field_type, Node n)
			throws PropertiesParseException {
		try {

			String nodeValue = getElementValue(document, n);

			if (nodeValue == null)
				return null;
			if (MultiFormatProperties.class.isAssignableFrom(field_type)) {
				Constructor<?> default_constructor = null;
				for (Constructor<?> c : field_type.getDeclaredConstructors()) {

					if (c.getParameterTypes().length == 0) {
						default_constructor = c;
						default_constructor.setAccessible(true);
						break;
					}
				}
				if (default_constructor == null) {
					throw new PropertiesParseException(
							"The class " + field_type.getCanonicalName() + " must have a default constructor ");
				}

				MultiFormatProperties e = (MultiFormatProperties) default_constructor.newInstance();
				if (e.optional_xml_object_parser_instance == null)
					e.optional_xml_object_parser_instance = optional_xml_object_parser_instance;
				e.read(document, n.getChildNodes());
				return e;
			} else
				return getValue(field_type, nodeValue);
		} catch (Exception e) {
			throw new PropertiesParseException(e,
					"Impossible to read the field " + field_name + " of the type " + field_type.getName());
		}
	}

	boolean isValid(Field field) {
		int mod = field.getModifiers();
		if (Modifier.isFinal(mod) || Modifier.isTransient(mod) || Modifier.isNative(mod) || Modifier.isStatic(mod))
			return false;
		return MultiFormatProperties.class.isAssignableFrom(field.getType()) || Map.class.isAssignableFrom(field.getType())
				|| List.class.isAssignableFrom(field.getType())
				|| Set.class.isAssignableFrom(field.getType())
				|| default_xml_object_parser_instance.isValid(field.getType())
				|| (optional_xml_object_parser_instance != null
						&& optional_xml_object_parser_instance.isValid(field.getType()));
	}

	/**
	 * Load properties from an XML document
	 * 
	 * @param document
	 *            the document to load
	 * @throws PropertiesParseException
	 *             if a problem of XML parse occurs
	 */
	public void loadXML(Document document) throws PropertiesParseException {
		if (document == null)
			throw new NullPointerException("document");

		Node n = getRootNode(document);
		if (n == null || n.getChildNodes() == null)
			throw new PropertiesParseException(
					"Impossible to find the node named " + this.getClass().getCanonicalName());

		NodeList nl = null;

		for (int i = 0; i < n.getChildNodes().getLength(); i++) {
			Node sn = n.getChildNodes().item(i);
			if (sn != null && sn.getNodeName().equals(this.getClass().getCanonicalName())) {
				nl = sn.getChildNodes();
				break;
			}
		}
		if (nl == null)
			throw new PropertiesParseException(
					"Impossible to find the node named " + this.getClass().getCanonicalName());
		/*
		 * else if (nl.getLength()>1) throw new
		 * XMLPropertiesParseException("The node named "+this.getClass().
		 * getCanonicalName()+" must be defined only one time");
		 */
		read(document, nl);
	}

	/**
	 * Load properties from an XML file
	 * 
	 * @param xml_file
	 *            the file to load
	 * @throws PropertiesParseException
	 *             if a problem parsing occurs
	 * @throws IOException
	 *             of a IO problem occurs
	 */
	public void loadXML(File xml_file) throws PropertiesParseException, IOException {
		try {
			Document d = getDOM(xml_file);
			loadXML(d);
		} catch (SAXException | ParserConfigurationException e) {
			throw new PropertiesParseException(e, "Impossible to read the XML file " + xml_file);
		}
	}

	/**
	 * Load properties from an XML input stream
	 * 
	 * @param is
	 *            the input stream
	 * @throws PropertiesParseException
	 *             if a problem parsing occurs
	 * @throws IOException
	 *             of a IO problem occurs
	 */
	public void loadXML(InputStream is) throws PropertiesParseException, IOException {
		try {
			if (is == null)
				throw new NullPointerException("is");
			Document d = getDOM(is);
			loadXML(d);
		} catch (SAXException | ParserConfigurationException e) {
			throw new PropertiesParseException(e, "Impossible to read the given input stream !");
		}
	}

	

	
	/**
	 * Load properties from {@link Properties} class.
	 * 
	 * 
	 * if one property does not exists, put the value into the free string
	 * properties returned by {@link #getFreeStringProperties()}.
	 * 
	 * @param properties
	 *            the properties
	 * @throws IllegalArgumentException
	 *             if a problem of parse occurs
	 */
	public void loadFromProperties(Properties properties) throws IllegalArgumentException {
		for (Entry<Object, Object> e : properties.entrySet()) {
			String key = (String) e.getKey();
			String value = (String) e.getValue();

			if (!MultiFormatProperties.this.setField(MultiFormatProperties.this, key.split("\\."), 0, value)) {
				getFreeStringProperties().put(key, value);
			}
		}
	}

	void read(Document document, NodeList node_list) throws PropertiesParseException {
		for (int i = 0; i < node_list.getLength(); i++) {
			Node node = node_list.item(i);
			String node_name = node.getNodeName();
			Class<?> c = this.getClass();
			boolean found = false;
			while (c != Object.class && !found) {
				for (Field f : c.getDeclaredFields()) {
					Class<?> type = equals(f, node_name);
					if (type != null && isValid(f)) {
						f.setAccessible(true);
						readField(document, f, type, node);
						found = true;
						break;
					}
				}
				c = c.getSuperclass();
			}
		}
	}

	private Class<?> equals(Field f, String node_name) {
		if (f.getName().equals(node_name))
			return f.getType();
		else if (MultiFormatProperties.class.isAssignableFrom(f.getType())) {
			try {
				Class<?> c = Class.forName(node_name.substring(0, node_name.lastIndexOf(".")));
				if (f.getType().isAssignableFrom(c))
					return c;
				else
					return null;
			} catch (Exception e) {
				return null;
			}
		}
		return null;
	}

	private Class<?> equals(Field f, String[] keys, AtomicInteger keyOff) {
		if (keys.length - keyOff.get() <= 0)
			return null;

		if (MultiFormatProperties.class.isAssignableFrom(f.getType())) {
			String[] fExplodedClass = f.getType().getName().split("\\.");

			if (keys.length - keyOff.get() - 2 < fExplodedClass.length)
				return null;
			for (int s = keys.length - 2; s >= fExplodedClass.length; s--) {
				StringBuilder cs = new StringBuilder();
				for (int i = keyOff.get(); i < s; i++) {
					if (cs.length() > 0)
						cs.append(".");
					cs.append(keys[i]);
				}
				try {
					Class<?> c = Class.forName(cs.toString());
					if (MultiFormatProperties.class.isAssignableFrom(f.getType()) && f.getName().equals(keys[s])) {
						keyOff.set(keyOff.get() + s + 1);
						return c;
					}
				} catch (Exception ignored) {

				}
			}

			return null;
		} else if (f.getName().equals(keys[keyOff.get()])) {
			keyOff.set(keyOff.get() + 1);
			return f.getType();
		}
		return null;
	}
	@SuppressWarnings("unchecked")
	private Collection<Object> initCollection(Class<?> type) throws NoSuchMethodException, IllegalAccessException, InvocationTargetException, InstantiationException {

		if (Set.class.isAssignableFrom(type))
		{
			{
				if (Modifier.isAbstract(type.getModifiers()))
					return new HashSet<>();
				else
				{
					return (Set<Object>)type.getDeclaredConstructor().newInstance();
				}

			}
		}
		else if (List.class.isAssignableFrom(type))
		{
			if (type.isArray()) {
				return new ArrayList<>();
			} else {

				if (Modifier.isAbstract(type.getModifiers())) {
					if (AbstractSequentialList.class.isAssignableFrom(type))
						return new LinkedList<>();
					else
						return new ArrayList<>();
				} else {
					return (List<Object>) type.getDeclaredConstructor().newInstance();
				}
			}
		}
		else
			throw new IllegalAccessError();
	}
	void readField(Document document, Field field, Class<?> type, Node node) throws PropertiesParseException {

		// deal with map
		if (Map.class.isAssignableFrom(type)) try {
			Map<Object, Object> m;
			if (Modifier.isAbstract(type.getModifiers())) {
				m = new HashMap<>();
			} else {
				@SuppressWarnings("unchecked")
				Map<Object, Object> newInstance = (Map<Object, Object>) type.getDeclaredConstructor().newInstance();
				m = newInstance;
			}

			/*
			 * Class<?> key_map_class= (Class<?>) ((ParameterizedType)
			 * field.getGenericType()).getActualTypeArguments()[0]; Class<?>
			 * value_map_class= (Class<?>) ((ParameterizedType)
			 * field.getGenericType()).getActualTypeArguments()[1];
			 */

			NodeList node_list = node.getChildNodes();
			for (int i = 0; i < node_list.getLength(); i++) {
				Node n = node_list.item(i);
				if (n.getNodeName().equals("ElementMap")) {
					Node keyn = null;
					Node valuen = null;
					NodeList ne = n.getChildNodes();

					for (int j = 0; j < ne.getLength() && !(keyn != null && valuen != null); j++) {
						Node n2 = ne.item(j);

						if (n2.getNodeName().equals("key"))
							keyn = n2;
						else if (n2.getNodeName().equals("value"))
							valuen = n2;
					}

					if (keyn != null && valuen != null) {
						Class<?> key_map_class = Class
								.forName(keyn.getAttributes().getNamedItem("ElementType").getNodeValue());
						Class<?> value_map_class = Class
								.forName(valuen.getAttributes().getNamedItem("ElementType").getNodeValue());

						Object okey = getValue(document, field.getName(), key_map_class, keyn);
						Object ovalue = getValue(document, field.getName(), value_map_class, valuen);

						if (!(okey != null && okey == Void.TYPE) && !(ovalue != null && ovalue == Void.TYPE)) {
							m.put(okey, ovalue);
						}
					}
				}
			}
			field.set(this, m);

		} catch (InstantiationException | IllegalAccessException | DOMException | ClassNotFoundException | IllegalArgumentException | InvocationTargetException | NoSuchMethodException | SecurityException e) {
			throw new PropertiesParseException(e, "Impossible to read the type " + type.getName());
		}
		else if (List.class.isAssignableFrom(type) || Set.class.isAssignableFrom(type))
			// TODO add array management
		{
			try {
				Collection<Object> collection=initCollection(type);


				// Class<?> element_list_class= (Class<?>) ((ParameterizedType)
				// field.getGenericType()).getActualTypeArguments()[0];
				NodeList node_list = node.getChildNodes();
				for (int i = 0; i < node_list.getLength(); i++) {
					Node n = node_list.item(i);
					if (n.getNodeName().equals("ElementList")) {
						Class<?> element_list_class = Class
								.forName(n.getAttributes().getNamedItem("ElementType").getNodeValue());
						Object o = getValue(document, field.getName(), element_list_class, n);
						if (!(o != null && o == Void.TYPE))
							collection.add(o);
					}
				}
				if (type.isArray()) {
					field.set(this, collection.toArray());
				} else {
					field.set(this, collection);
				}

			} catch (InstantiationException | IllegalAccessException | DOMException | ClassNotFoundException | IllegalArgumentException | InvocationTargetException | NoSuchMethodException | SecurityException e) {
				throw new PropertiesParseException(e, "Impossible to read the type " + type.getName());
			}

		}
		else if (MultiFormatProperties.class.isAssignableFrom(type)) {
			// deal with Properties instance

			try {
				MultiFormatProperties p = (MultiFormatProperties) field.get(this);
				if (p == null) {
					Constructor<?> default_constructor = null;
					for (Constructor<?> c : type.getDeclaredConstructors()) {

						if (c.getParameterTypes().length == 0) {
							default_constructor = c;
							default_constructor.setAccessible(true);
							break;
						}
					}
					if (default_constructor == null) {
						throw new PropertiesParseException(
								"The class " + type.getCanonicalName() + " must have a default constructor ");
					}

					p = (MultiFormatProperties) default_constructor.newInstance();
					field.set(this, p);
				}
				if (p.optional_xml_object_parser_instance == null)
					p.optional_xml_object_parser_instance = optional_xml_object_parser_instance;
				p.read(document, node.getChildNodes());
			} catch (InstantiationException | IllegalAccessException | IllegalArgumentException
					| InvocationTargetException e) {
				throw new PropertiesParseException(e, "Impossible to read the type " + type.getName());
			}
		} else if (type.isPrimitive()) {

			// deal with primitive type
			try {
				String nodeValue = node.getTextContent();
				if (nodeValue == null)
					return;
				if (type == boolean.class) {
					field.setBoolean(this, Boolean.parseBoolean(nodeValue));
				} else if (type == byte.class) {
					field.setByte(this, Byte.parseByte(nodeValue));
				} else if (type == short.class) {
					field.setShort(this, Short.parseShort(nodeValue));
				} else if (type == int.class) {
					field.setInt(this, Integer.parseInt(nodeValue));
				} else if (type == long.class) {
					field.setLong(this, Long.parseLong(nodeValue));
				} else if (type == float.class) {
					field.setFloat(this, Float.parseFloat(nodeValue));
				} else if (type == double.class) {
					field.setDouble(this, Double.parseDouble(nodeValue));
				} else if (type == char.class) {
					field.setChar(this, nodeValue.charAt(0));
				} else
					throw new PropertiesParseException("Unknown primitive type " + type.getName());

			} catch (IllegalArgumentException | IllegalAccessException e) {
				throw new PropertiesParseException(e, "Impossible read the field " + field.getName());
			}
		} else {
			try {
				Object o = getValue(document, field.getName(), type, node);
				if (!(o != null && o == Void.TYPE))
					field.set(this, o);
			} catch (IllegalArgumentException | IllegalAccessException | DOMException e) {
				throw new PropertiesParseException(e, "Impossible read the field " + field.getName());
			}

		}
	}
    /**
     * Save properties into an XML document
     *
     * @param doc
     *            the document
     * @throws PropertiesParseException
     *             if a problem of XML parse occurs
     */
    public void saveXML(Document doc) throws PropertiesParseException {
        saveXML(doc, null);
    }
	/**
	 * Save properties into an XML document
	 * 
	 * @param doc
	 *            the document
     * @param referenceProperties the reference properties. If a property is the same between this instance and the given reference, that the properties is not saved into the file
	 * @throws PropertiesParseException
	 *             if a problem of XML parse occurs
	 */
	public void saveXML(Document doc, MultiFormatProperties referenceProperties) throws PropertiesParseException {
		try {
			Node root = doc.createElement(this.getClass().getCanonicalName());
			if (write(doc, root, referenceProperties))
				createOrGetRootNode(doc).appendChild(root);
		} catch (DOMException e) {
			throw new PropertiesParseException(e, "");
		}
	}
    /**
     * Save properties into an XML file
     *
     * @param xml_file
     *            the file to save
     * @throws PropertiesParseException
     *             if a problem of XML parse occurs
     */
    public void saveXML(File xml_file) throws PropertiesParseException {
        saveXML(xml_file, null);
    }

	/**
	 * Save properties into an XML file
	 * 
	 * @param xml_file
	 *            the file to save
     * @param referenceProperties the reference properties. If a property is the same between this instance and the given reference, that the properties is not saved into the file
	 * @throws PropertiesParseException
	 *             if a problem of XML parse occurs
	 */
	public void saveXML(File xml_file, MultiFormatProperties referenceProperties) throws PropertiesParseException {
		try {
			DocumentBuilderFactory docFactory = DocumentBuilderFactory.newInstance();
			DocumentBuilder docBuilder = docFactory.newDocumentBuilder();

			// root elements
			Document doc = docBuilder.newDocument();
			doc.setXmlStandalone(true);
			saveXML(doc, referenceProperties);

			TransformerFactory transformerFactory = TransformerFactory.newInstance();
			Transformer transformer = transformerFactory.newTransformer();
			DOMSource source = new DOMSource(doc);
			StreamResult result = new StreamResult(xml_file);
			transformer.setOutputProperty(OutputKeys.METHOD, "xml");
			transformer.setOutputProperty(OutputKeys.INDENT, "yes");
			transformer.setOutputProperty(OutputKeys.STANDALONE, "yes");
			transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "4");
			transformer.transform(source, result);
		} catch (ParserConfigurationException | TransformerException e) {
			throw new PropertiesParseException(e, "");
		}
	}
    /**
     * Save properties into an YAML file
     *
     * @param yaml_file
     *            the file to save
     * @throws IOException if a problem occurs
     */
    public void saveYAML(File yaml_file) throws IOException
    {
        saveYAML(yaml_file, null);
    }
	/**
	 * Save properties into an YAML file that are different from the reference
	 * 
	 * @param yaml_file
	 *            the file to save
     * @param referenceProperties the reference properties. If a property is the same between this instance and the given reference, that the properties is not saved into the file
     *
	 * @throws IOException if a problem occurs
	 */
	public void saveYAML(File yaml_file, MultiFormatProperties referenceProperties) throws IOException
	{
		
		
		Yaml yaml=new Yaml(new YamlRepresenting(referenceProperties),getDumperOptions());

		yaml.setBeanAccess(BeanAccess.FIELD);
		yaml.setName(this.getClass().getSimpleName());
		try(FileWriter fw = new FileWriter(yaml_file))
		{
			yaml.dump(this, fw);
		}
		
	}
	
	private DumperOptions getDumperOptions()
	{
		DumperOptions options = new DumperOptions();
		options.setAllowUnicode(true);
		options.setAllowReadOnlyProperties(false);
		options.setIndent(4);
		return options;
	}
	
	/**
	 * Load properties from an YAML file
	 * 
	 * @param yamlFile
	 *            the file name
	 *
	 * @throws IOException if a problem occurs
	 */
	public void loadYAML(File yamlFile) throws IOException {
		
		try(FileReader fr=new FileReader(yamlFile))
		{
			loadYAML(fr);
		}
	}
	public void loadYAML(Reader reader) throws IOException {
		ConstructorYaml constructor=new ConstructorYaml();
		Yaml yaml=new Yaml(constructor);
		yaml.setBeanAccess(BeanAccess.FIELD);
		if (yaml.load(reader)!=this)
			throw new IOException();
	}
	public void loadYAML(InputStream input) throws IOException {
		try(InputStreamReader fr=new InputStreamReader(input))
		{
			loadYAML(fr);
		}
	}

	private boolean canExclude(MultiFormatProperties mfp, String fieldName, Object propertyValue)  {
        if (mfp!=null && mfp.getClass()==this.getClass())
        {
            try {
                Field f=this.getClass().getDeclaredField(fieldName);
                f.setAccessible(true);
                return canExclude(mfp, f, propertyValue, true);
            } catch (NoSuchFieldException ignored) {
                return false;
            } catch (IllegalAccessException e) {
                e.printStackTrace();
                return false;
            }
        }
        return false;
    }
    private boolean canExclude(MultiFormatProperties mfp, Field field, Object value) throws IllegalAccessException {
	    return canExclude(mfp, field, value, false);
    }
    private boolean canExclude(MultiFormatProperties mfp, Field field, Object value, boolean noTestMFP) throws IllegalAccessException {
        if (noTestMFP || (mfp!=null && mfp.getClass()==this.getClass()))
        {
            Object reference=field.get(mfp);
            if (reference!=null && value!=null)
            {
                if (field.getType().isAssignableFrom(MultiFormatProperties.class))
                    return canExclude((MultiFormatProperties)reference, (MultiFormatProperties)value);
                else if (field.getDeclaringClass().isAssignableFrom(Map.class))
                {
                    return canExclude((Map<?, ?>)value, (Map<?, ?>)reference);
                }
                else if (field.getDeclaringClass().isAssignableFrom(List.class) || field.getDeclaringClass().isAssignableFrom(Set.class))
				{
					return canExclude((Collection<?>)value, (Collection<?>)value);
				}

            }
            return Objects.equals(reference, value);
        }
        return false;
    }

    private boolean canExclude(MultiFormatProperties mfp, MultiFormatProperties value) throws IllegalAccessException {
        Class<?> c = value.getClass();
        while (c != Object.class) {
            for (Field field : c.getDeclaredFields())
            {
                if (isValid(field))
                {
                    field.setAccessible(true);
                    if (!canExclude(mfp, field, field.get(value)))
                        return false;
                }
            }
            c = c.getSuperclass();
        }

        return true;
    }

    private boolean canExclude(Map<?, ?> value, Map<?, ?> reference)  {
	    if (value.size()!=reference.size())
	        return false;
	    for (Map.Entry<?, ?> e : value.entrySet())
        {
            if (!reference.containsKey(e.getKey()))
                return false;
            Object o=reference.get(e.getKey());

            if (o!=e.getValue() && o!=null && !o.equals(e.getValue()))
                return false;
        }

        return true;
    }

    private boolean canExclude(Collection<?> value, Collection<?> reference) {
        if (value.size()!=reference.size())
            return false;
        for (Object v : value)
        {
            if (!reference.contains(v))
                return false;
        }

        return true;
    }


	private class YamlRepresenting extends Representer
	{
		final MultiFormatProperties mfp;
		YamlRepresenting(MultiFormatProperties mfp)
		{
		    if (mfp!=null && mfp.getClass()==MultiFormatProperties.this.getClass())
			    this.mfp=mfp;
		    else
		        this.mfp=null;
			init(default_xml_object_parser_instance);
			if (optional_xml_object_parser_instance!=null)
				init(optional_xml_object_parser_instance);

		}

        @Override
        protected NodeTuple representJavaBeanProperty(Object javaBean, Property property, Object propertyValue, Tag customTag) {

            if (canExclude(mfp, property.getName(), propertyValue)) {
                return null;
            }
            else {
                return super.representJavaBeanProperty(javaBean, property, propertyValue, customTag);
            }
        }

		private void init (AbstractMultiFormatObjectParser parser)
		{
            representers.remove(Calendar.class);
            multiRepresenters.remove(Calendar.class);
			for (Class<?> c : parser.getSupportedClasses())
			{
				if (isPersonalizedYAMLSerialization(c) && (!representers.containsKey(c)))
					representers.put(c, new YamlRepresent(parser, c));
			}
			for (Class<?> c : parser.getSupportedMultiClasses())
			{
				if (isPersonalizedYAMLSerialization(c) && (!multiRepresenters.containsKey(c)))
					multiRepresenters.put(c, new YamlRepresent(parser, c));
			}
		}
		
		private class YamlRepresent implements Represent
		{
			private final AbstractMultiFormatObjectParser parser;
			private final Class<?> clazz;
			
			YamlRepresent(AbstractMultiFormatObjectParser parser, Class<?> clazz)
			{
				this.parser=parser;
				this.clazz=clazz;
				
			}
			
			
			
			@Override
			public org.yaml.snakeyaml.nodes.Node representData(Object data) {
				try {
					String value=parser.convertObjectToString(clazz, data);
					return representScalar(MultiFormatProperties.getTag(data.getClass()), value);
				} catch (Exception e) {
					e.printStackTrace();
					return null;
				}
				
			}
		}
		
		
		
	}
	
	private boolean isPersonalizedYAMLSerialization(Class<?> c)
	{
		return String.class!=c && !Number.class.isAssignableFrom(c) && !c.isPrimitive() && !c.isEnum() && !c.isAssignableFrom(MultiFormatProperties.class) && !Collection.class.isAssignableFrom(c) && !Map.class.isAssignableFrom(c) && !c.isArray();
	}
	
	private static Tag getTag(Class<?> clazz)
	{
		if (AbstractDecentralizedID.class.isAssignableFrom(clazz))
			return new Tag(Tag.PREFIX+"decentralizedID");
		else if (InetAddress.class.isAssignableFrom(clazz))
			return new Tag(Tag.PREFIX+"ip");
		else if (InetSocketAddress.class.isAssignableFrom(clazz))
			return new Tag(Tag.PREFIX+"ipp");
		else if (URI.class==clazz)
			return new Tag(Tag.PREFIX+"uir");
		else if (URL.class==clazz)
			return new Tag(Tag.PREFIX+"url");
		else if (File.class==clazz)
			return new Tag(Tag.PREFIX+"file");
		else if (Class.class==clazz)
			return new Tag(Tag.PREFIX+"class");
		else if (Level.class==clazz)
			return new Tag(Tag.PREFIX+"logLevel");
		else
			return new Tag(clazz);

	}
	
	private class ConstructorYaml extends org.yaml.snakeyaml.constructor.Constructor
	{
		private boolean setFirstTime=false;
		protected final Map<Tag, Construct> yamlAbstractConstructors = new HashMap<>();
		ConstructorYaml()
		{
			init(default_xml_object_parser_instance);
			if (optional_xml_object_parser_instance!=null)
				init(optional_xml_object_parser_instance);
			//yamlClassConstructors.put(NodeId.mapping, new RootConstruct());
			
		}
	
		
		@Override
		protected Construct getConstructor(org.yaml.snakeyaml.nodes.Node node) {
			
	        if (node.useClassConstructor()) {
	            return yamlClassConstructors.get(node.getNodeId());
	        } else {
	            Construct constructor = yamlConstructors.get(node.getTag());
	            if (constructor == null) {
	            	for (Map.Entry<Tag, Construct> e: yamlAbstractConstructors.entrySet())
	            	{
	            		try {
							if (node.getTag().getValue().equals(e.getKey().getValue()) || (e.getKey().getValue().startsWith(Tag.PREFIX) && e.getKey().getClassName().contains(".") && Class.forName(e.getKey().getClassName()).isAssignableFrom(node.getType())))
							{
								return e.getValue();
							}
						} catch (ClassNotFoundException e1) {
							e1.printStackTrace();
						}
	            		
	            	}
	                for (String prefix : yamlMultiConstructors.keySet()) {
	                    if (node.getTag().startsWith(prefix)) {
	                        return yamlMultiConstructors.get(prefix);
	                    }
	                }
	                return yamlConstructors.get(null);
	            }
	            return constructor;
	        }
	    }
		@Override
		protected Object newInstance(Class<?> ancestor, org.yaml.snakeyaml.nodes.Node node, boolean tryDefault)
	            throws InstantiationException {
			
			super.newInstance(ancestor, node, tryDefault);
			if (setFirstTime)
				return super.newInstance(ancestor, node, tryDefault);
			else
			{
				setFirstTime=true;
				return MultiFormatProperties.this;
			}
		}

		/*private void removeCalendar(Map<Tag, Class<?>> m)
        {
            for (Iterator<Map.Entry<Tag, Class<?>>> it=m.entrySet().iterator();it.hasNext();)
            {
                try {
                    if (Calendar.class.isAssignableFrom(Class.forName(it.next().getKey().getClassName())))
                        it.remove();
                } catch (ClassNotFoundException e) {
                    e.printStackTrace();
                }
            }
        }*/
		private void init (AbstractMultiFormatObjectParser parser)
		{

		    yamlConstructors.remove(getTag(Calendar.class));
            yamlAbstractConstructors.remove(getTag(Calendar.class));
			for (Class<?> c : parser.getSupportedClasses())
			{
				//String k=c.getName();
				Tag t=getTag(c);
				if (isPersonalizedYAMLSerialization(c) && (!yamlConstructors.containsKey(t)))
					yamlConstructors.put(t, new ConstructYaml(parser, c));
			}
			for (Class<?> c : parser.getSupportedMultiClasses())
			{
				Tag t=getTag(c);
				if (isPersonalizedYAMLSerialization(c) && (!yamlAbstractConstructors.containsKey(t)))
					yamlAbstractConstructors.put(t, new ConstructYaml(parser, c));
			}
			
		}
		
		
		
		private class ConstructYaml extends AbstractConstruct
		{
			private final AbstractMultiFormatObjectParser parser;
			private final Class<?> clazz;
			ConstructYaml(AbstractMultiFormatObjectParser parser, Class<?> clazz)
			{
				this.parser=parser;
				this.clazz=clazz;
			}
		

			@Override
			public Object construct(org.yaml.snakeyaml.nodes.Node node) {
				String value = constructScalar((ScalarNode)node);
				try {
					return parser.convertStringToObject(clazz, value);
				} catch (Exception e) {
					e.printStackTrace();
					return null;
				}
			}
		}
		
		/*private class RootConstruct extends ConstructMapping
		{
			private boolean root=true;
			@Override
			 protected Object createEmptyJavaBean(MappingNode node) {
		            if (root)
		            {
		            	root=false;
		            	return MultiFormatProperties.this;
		            }
		            else
		            {
		            	return super.createEmptyJavaBean(node);
		            }
		        }
		}
	*/
	}
	
	
	
	@SuppressWarnings("unchecked")
	void setField(Field field, String value) throws IllegalArgumentException {
		try {
			Class<?> field_type = field.getType();
			if (field_type.isPrimitive()) {
				if (value != null){
					if (field_type == boolean.class) {
						field.setBoolean(this, Boolean.parseBoolean(value));
					} else if (field_type == byte.class) {
						field.setByte(this, Byte.parseByte(value));
					} else if (field_type == short.class) {
						field.setShort(this, Short.parseShort(value));
					} else if (field_type == int.class) {
						field.setInt(this, Integer.parseInt(value));
					} else if (field_type == long.class) {
						field.setLong(this, Long.parseLong(value));
					} else if (field_type == float.class) {
						field.setFloat(this, Float.parseFloat(value));
					} else if (field_type == double.class) {
						field.setDouble(this, Double.parseDouble(value));
					} else if (field_type == char.class) {
						field.setChar(this, value.charAt(0));
					}

				}
			} else if (List.class.isAssignableFrom(field_type) || Set.class.isAssignableFrom(field_type)) {
				if (value == null || value.equals("null"))
					field.set(this, null);
				else {

					Class<?> element_list_class = getGenericType(field);
					Collection<Object> collection=initCollection(field_type);

					if (value.startsWith("{") && value.endsWith("}")) {
						value = value.substring(1, value.length() - 1);
						for (String v : value.split(";")) {
							Object o = getValue(element_list_class, v);
							if (o != null && o != Void.TYPE)
								collection.add(o);
						}

						field.set(this, collection);
					}
				}

			} else if (Map.class.isAssignableFrom(field_type)) {

				Map<Object, Object> m = null;
				if (!value.equals("null")) {
					if (Modifier.isAbstract(field_type.getModifiers())) {
						m = new HashMap<>();
					} else {
						m = (Map<Object, Object>) field_type.getDeclaredConstructor().newInstance();
					}

					if (value.startsWith("{") && value.endsWith("}")) {
						value = value.substring(1, value.length() - 1);
						for (String v : value.split(";")) {
							String[] split = v.split(":");
							if (split.length == 4 && !split[0].equals("null")) {
								Class<?> key_map_class = Class.forName(split[0]);
								Class<?> value_map_class = null;
								if (!split[2].equals("null"))
									value_map_class = Class.forName(split[2]);

								Object ok = getValue(key_map_class, split[1]);
								if (ok == null || ok != Void.TYPE) {
									Object ov = null;
									if (value_map_class != null)
										ov = getValue(value_map_class, split[3]);
									if (ov == null || ov != Void.TYPE)
										m.put(ok, ov);
								}
							}

						}

					}
				}
				field.set(this, m);
			} else {
				Object o = getValue(field_type, value);
				if (o == null || !(o == Void.TYPE))
					field.set(this, o);
			}
		} catch (Exception e) {
			throw new IllegalArgumentException(
					"Impossible to read the field " + field.getName() + " of the type " + field.getType(), e);
		}
	}

	boolean setField(MultiFormatProperties instance, String[] keys, int current_index, String value)
			throws IllegalArgumentException {
		try {
			if (instance == null)
				return false;
			Class<?> c = instance.getClass();
			while (c != Object.class) {
				for (Field f : c.getDeclaredFields()) {
					AtomicInteger off = new AtomicInteger(current_index);
					Class<?> type = equals(f, keys, off);
					if (type != null && isValid(f)) {
						f.setAccessible(true);
						if (current_index == keys.length - 1) {
							instance.setField(f, value);
							return true;
						} else {
							if (MultiFormatProperties.class.isAssignableFrom(type)) {
								boolean toreload = false;
								MultiFormatProperties i = (MultiFormatProperties) f.get(instance);
								if (i == null) {
									toreload = true;
									Constructor<?> construct = type.getDeclaredConstructor();
									construct.setAccessible(true);
									i = (MultiFormatProperties) construct.newInstance();
								}

								boolean ok = setField(i, keys, off.get(), value);
								if (ok && toreload)
									f.set(instance, i);
								return ok;
							} else
								return false;
						}

					}
				}
				c = c.getSuperclass();
			}
			return false;
		} catch (IllegalAccessException | InstantiationException | NoSuchMethodException | SecurityException
				| InvocationTargetException e) {
			throw new IllegalArgumentException(e);
		}
	}

	boolean setTextContent(Document document, Node node, String field_name, Class<?> field_type, Object object, MultiFormatProperties referenceProperties)
			throws PropertiesParseException {
		try {
			if (object == null) {
				node.setTextContent(null);
				return false;
			} else if (MultiFormatProperties.class.isAssignableFrom(field_type)) {
				MultiFormatProperties e = (MultiFormatProperties) object;
				if (e.optional_xml_object_parser_instance == null)
					e.optional_xml_object_parser_instance = optional_xml_object_parser_instance;
				return e.write(document, node, referenceProperties);
			} else {
				String res = getString(field_type, object);
				if (res == null) {
					return false;
				} else {
					node.setTextContent(res);
					return true;
				}
			}
		} catch (Exception e) {
			throw new PropertiesParseException(e,
					"Impossible to write the field " + field_name + " of the type " + field_type.getName());
		}
	}

	boolean write(Document document, Node element, MultiFormatProperties referenceProperties) throws PropertiesParseException {
		Class<?> c = this.getClass();
		while (c != Object.class) {
			for (Field f : c.getDeclaredFields()) {
				if (isValid(f)) {
					f.setAccessible(true);
                    try {
                        if (!canExclude(referenceProperties, f, f.get(this)))
                            writeField(document, element, f, referenceProperties);
                    } catch (IllegalAccessException e) {
                        throw new PropertiesParseException(e, "");
                    }
                }
			}
			c = c.getSuperclass();
		}
		return true;
	}

	void writeField(Document document, Node parent_element, Field field, MultiFormatProperties referenceProperties) throws PropertiesParseException {
		Class<?> type = field.getType();
		if (optional_xml_object_parser_instance != null && optional_xml_object_parser_instance.isValid(type)) {
			try {
				Element element = document.createElement(field.getName());
				if (setTextContent(document, element, field.getName(), field.getType(), field.get(this), referenceProperties))
					parent_element.appendChild(element);
			} catch (IllegalArgumentException | IllegalAccessException | DOMException e) {
				throw new PropertiesParseException(e, "Impossible read the field " + field.getName());
			}
		} else if (Map.class.isAssignableFrom(type)) {

			// deal with map

			try {

				@SuppressWarnings("unchecked")
				Map<Object, Object> m = (Map<Object, Object>) field.get(this);
				if (m == null)
					return;
				Element element = document.createElement(field.getName());

				for (Entry<Object, Object> entry : m.entrySet()) {
					Element elementM = document.createElement("ElementMap");
					Element key = document.createElement("key");
					/*
					 * Attr attr_key=document.createAttribute("type");
					 * attr_key.setValue(key_map_class.getCanonicalName());
					 * key.setAttributeNode(attr_key);
					 */
					elementM.appendChild(key);
					Object k = entry.getKey();
					if (setTextContent(document, key, field.getName(), k == null ? null : k.getClass(), k, referenceProperties)) {
						key.setAttribute("ElementType", k == null ? null : k.getClass().getCanonicalName());
						Element value = document.createElement("value");
						/*
						 * Attr attr_value=document.createAttribute("type");
						 * attr_value.setValue(value_map_class.getCanonicalName( ));
						 * key.setAttributeNode(attr_value);
						 */

						elementM.appendChild(value);
						Object v = entry.getValue();
						if (setTextContent(document, value, field.getName(), v == null ? null : v.getClass(), v, referenceProperties)) {
							value.setAttribute("ElementType", v == null ? null : v.getClass().getCanonicalName());
							element.appendChild(elementM);
						}
					}
				}
				parent_element.appendChild(element);
			} catch (IllegalAccessException | DOMException e) {
				throw new PropertiesParseException(e, "Impossible to read the type " + type.getName());
			}

		} else if (List.class.isAssignableFrom(type) || Set.class.isAssignableFrom(type)) {
			// deal with list

			try {
				@SuppressWarnings("unchecked")
				Collection<Object> l = (Collection<Object>) field.get(this);
				if (l == null)
					return;

				Class<?> element_list_class = getGenericType(field);

				Element element = document.createElement(field.getName());

				for (Object o : l) {
					Element elemL = document.createElement("ElementList");

					/*
					 * Attr attr=document.createAttribute("type");
					 * attr.setValue(o.getClass().getCanonicalName()); elemL.setAttributeNode(attr);
					 */
					if (setTextContent(document, elemL, field.getName(), o == null ? element_list_class : o.getClass(),
							o, referenceProperties)) {
						elemL.setAttribute("ElementType",
								o == null ? element_list_class.getCanonicalName() : o.getClass().getCanonicalName());
						element.appendChild(elemL);
					}
				}
				parent_element.appendChild(element);
			} catch (IllegalAccessException | DOMException e) {
				throw new PropertiesParseException(e, "Impossible to read the type " + type.getName());
			}
		} // TODO add array management
		/*
		 * else if (type.isArray()) { //deal with array
		 * 
		 * try { Object l[]=(Object[]) field.get(this);
		 * 
		 * Class<?> element_list_class= (Class<?>) ((ParameterizedType)
		 * field.getGenericType()).getActualTypeArguments()[0];
		 * 
		 * Element element=document.createElement(field.getName());
		 * 
		 * for (Object o : l) { Element elemL=document.createElement("ElementList"); if
		 * (setTextContent(document, elemL, field.getName(), element_list_class, o)) {
		 * element.appendChild(elemL); } } parent_element.appendChild(element); } catch
		 * (IllegalAccessException | DOMException e) { throw new
		 * XMLPropertiesParseException(e,
		 * "Impossible to read the type "+type.getName()); }
		 * 
		 * }
		 */
		else if (MultiFormatProperties.class.isAssignableFrom(type)) {
			// deal with Properties instance

			try {
				MultiFormatProperties p = (MultiFormatProperties) field.get(this);
				if (p != null) {
					if (p.optional_xml_object_parser_instance == null)
						p.optional_xml_object_parser_instance = optional_xml_object_parser_instance;
					Element element = document.createElement(p.getClass().getName() + "." + field.getName());
					if (p.write(document, element, referenceProperties))
						parent_element.appendChild(element);
				}
			} catch (IllegalAccessException e) {
				throw new PropertiesParseException(e, "Impossible to read the type " + type.getName());
			}
		} else if (type.isPrimitive()) {

			// deal with primitive type
			try {
				Element element = document.createElement(field.getName());

				if (type == boolean.class) {
					element.setTextContent(Boolean.toString(field.getBoolean(this)));
				} else if (type == byte.class) {
					element.setTextContent(Byte.toString(field.getByte(this)));
				} else if (type == short.class) {
					element.setTextContent(Short.toString(field.getShort(this)));
				} else if (type == int.class) {
					element.setTextContent(Integer.toString(field.getInt(this)));
				} else if (type == long.class) {
					element.setTextContent(Long.toString(field.getLong(this)));
				} else if (type == float.class) {
					element.setTextContent(Float.toString(field.getFloat(this)));
				} else if (type == double.class) {
					element.setTextContent(Double.toString(field.getDouble(this)));
				} else if (type == char.class) {
					element.setTextContent(Character.toString(field.getChar(this)));
				} else
					return;
				parent_element.appendChild(element);

			} catch (IllegalArgumentException | IllegalAccessException e) {
				throw new PropertiesParseException(e, "Impossible read the field " + field.getName());
			}
		} else {
			try {
				Element element = document.createElement(field.getName());
				if (setTextContent(document, element, field.getName(), field.getType(), field.get(this), referenceProperties))
					parent_element.appendChild(element);
			} catch (IllegalArgumentException | IllegalAccessException | DOMException e) {
				throw new PropertiesParseException(e, "Impossible read the field " + field.getName());
			}

		}
	}

}

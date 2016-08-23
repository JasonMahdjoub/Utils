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
package com.distrimind.util.tests.properties;

import java.io.File;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.logging.Level;

import javax.lang.model.SourceVersion;

import org.testng.Assert;

import com.distrimind.util.Utils;
import com.distrimind.util.crypto.ASymmetricEncryptionType;
import com.distrimind.util.crypto.MessageDigestType;
import com.distrimind.util.crypto.SymmetricSecretKeyType;
import com.distrimind.util.properties.AbstractXMLObjectParser;
import com.distrimind.util.properties.XMLProperties;
import com.distrimind.util.version.Version;

/**
 * 
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 1.6.1
 */
public class PropertiesExample extends XMLProperties
{

    /**
     * 
     */
    private static final long serialVersionUID = -569461229020640634L;

    int intValue=0;
    short shortValue=0;
    byte byteValue=0;
    boolean booleanValue=false;
    long longValue=0;
    float floatValue=0.0f;
    double doubleValue=0.0f;
    
    Integer IntegerValue=null;
    Short ShortValue=null;
    Byte ByteValue=null;
    Boolean BooleanValue=null;
    Long LongValue=null;
    Float FloatValue=null;
    Double DoubleValue=null;
    
    String stringValue=null;
    File fileValue=null;
    URL urlValue=null;
    Level levelValue=null;
    InetAddress inetAddressV4=null;
    InetAddress inetAddressV6=null;
    InetSocketAddress inetSocketAddressV4=null;
    InetSocketAddress inetSocketAddressV6=null;
    SourceVersion sourceVersion=null;
    ASymmetricEncryptionType typeEncryption=null;
    MessageDigestType messageDigestType=null;
    SymmetricSecretKeyType symmetricSecretKeyType=null; 
    Class<?> className=null;
    Date date=null;
    Calendar calendar=null;
    
    Map<String, Integer> map=null;
    HashMap<String, Integer> map2=null;
    List<String> list=null;
    List<String> list2=null;
    ArrayList<String> list3=null;
    LinkedList<String> list4=null;
    
    SubProperties subProperties=null;
    Version version=null;
    
    protected PropertiesExample(AbstractXMLObjectParser _optional_xml_object_parser_instance)
    {
	super(_optional_xml_object_parser_instance);
    }
    
    void generateValues() throws MalformedURLException, UnknownHostException
    {
	Random rand=new Random(System.currentTimeMillis());
	intValue=rand.nextInt();
	shortValue=(short)rand.nextInt();
	byteValue=(byte)rand.nextInt();
	booleanValue=rand.nextBoolean();
	longValue=rand.nextLong();
	floatValue=rand.nextFloat();
	doubleValue=rand.nextDouble();
	
	IntegerValue=new Integer(rand.nextInt());
	ShortValue=new Short((short)rand.nextInt());
	ByteValue=new Byte((byte)rand.nextInt());
	BooleanValue=new Boolean(rand.nextBoolean());
	LongValue=new Long(rand.nextLong());
	FloatValue=new Float(rand.nextFloat());
	DoubleValue=new Double(rand.nextDouble());
	
	
	stringValue=getString(rand);
	fileValue=new File(getString(rand));
	urlValue=new URL("http://"+getString(rand)+".com");
	levelValue=rand.nextInt()%2==0?Level.CONFIG:Level.FINER;
	inetAddressV4=InetAddress.getByName("125.54.47.55");
	inetAddressV6=InetAddress.getByName("1242:1025:1258:1568:1224:1485:1569:2114");
	inetSocketAddressV4=new InetSocketAddress(inetAddressV4, rand.nextInt(5000));
	inetSocketAddressV6=new InetSocketAddress(inetAddressV6, rand.nextInt(5000));
	sourceVersion=SourceVersion.RELEASE_3;
	typeEncryption=ASymmetricEncryptionType.RSA_OAEPWithSHA256AndMGF1Padding;
	messageDigestType=MessageDigestType.SHA;
	symmetricSecretKeyType=SymmetricSecretKeyType.DESede;
	className=SubProperties.class;
	map=new HashMap<>();
	for (int i=0;i<10;i++)
	    map.put(getString(rand), new Integer(rand.nextInt()));
	map2=(HashMap<String, Integer>)map;
	list=new ArrayList<>();
	for (int i=0;i<10;i++)
	    list.add(getString(rand));
	list2=new LinkedList<>();
	for (int i=0;i<10;i++)
	    list2.add(getString(rand));
	list3=(ArrayList<String>)list;
	list4=(LinkedList<String>)list2;
	
	subProperties=new SubProperties();
	subProperties.value=getString(rand);
	for (int i=0;i<10;i++)
	    getFreeStringProperties().put(getString(rand), getString(rand));
	
	date=new Date(rand.nextLong());
	calendar=Calendar.getInstance();
	calendar.setTime(new Date(rand.nextLong()));
	version=Utils.VERSION;
    }
    
    private static String[] strings={"sfdg","fdgdg","bjf", "fsgh", "hlqoit"}; 
    
    String getString(Random rand)
    {
	return strings[rand.nextInt(strings.length)];
    }
    
    @Override
    public boolean equals(Object o)
    {
	if (o==null)
	    return false;
	if (o==this)
	    return true;
	if (o instanceof PropertiesExample)
	{
	    PropertiesExample pe=(PropertiesExample)o;
	    if (intValue!=pe.intValue)
		return false;
	    if (shortValue!=pe.shortValue)
		return false;
	    if (longValue!=pe.longValue)
		return false;
	    if (byteValue!=pe.byteValue)
		return false;
	    if (booleanValue!=pe.booleanValue)
		return false;
	    if (floatValue!=pe.floatValue)
		return false;
	    if (doubleValue!=pe.doubleValue)
		return false;
	    
	    if (!equals(IntegerValue, pe.IntegerValue))
		return false;
	    if (!equals(ShortValue, pe.ShortValue))
		return false;
	    if (!equals(LongValue, pe.LongValue))
		return false;
	    if (!equals(ByteValue, pe.ByteValue))
		return false;
	    if (!equals(BooleanValue, pe.BooleanValue))
		return false;
	    if (!equals(FloatValue, pe.FloatValue))
		return false;
	    if (!equals(DoubleValue, pe.DoubleValue))
		return false;

	    if (!equals(stringValue, pe.stringValue))
		return false;
	    if (!equals(fileValue, pe.fileValue))
		return false;
	    if (!equals(urlValue, pe.urlValue))
		return false;
	    if (!equals(levelValue, pe.levelValue))
		return false;
	    if (!equals(inetAddressV4, pe.inetAddressV4))
		return false;
	    if (!equals(inetAddressV6, pe.inetAddressV6))
		return false;
	    if (!equals(inetSocketAddressV4, pe.inetSocketAddressV4))
		return false;
	    if (!equals(inetSocketAddressV6, pe.inetSocketAddressV6))
		return false;

	    if (!equals(sourceVersion, pe.sourceVersion))
		return false;
	    if (!equals(typeEncryption, pe.typeEncryption))
		return false;
	    if (!equals(messageDigestType, pe.messageDigestType))
		return false;
	    if (!equals(symmetricSecretKeyType, pe.symmetricSecretKeyType))
		return false;
	    if (!equals(subProperties, pe.subProperties))
		return false;
	    
	    if (!equals(map, pe.map))
		return false;
	    if (!equals(map2, pe.map2))
		return false;
	    if (!equals(list, pe.list))
		return false;
	    if (!equals(list2, pe.list2))
		return false;
	    if (!equals(list3, pe.list3))
		return false;
	    if (!equals(list4, pe.list4))
		return false;
	    if (!equals(className, pe.className))
		return false;
	    if (!equals(getFreeStringProperties(), pe.getFreeStringProperties()))
		return false;
	    if (!equals(date, pe.date))
		return false;
	    if (!equals(calendar, pe.calendar))
		return false;
	    
	    Assert.assertFalse(version==null^pe.version==null);
	    if (version==null^pe.version==null)
	    {
		Assert.assertEquals(version.getAlphaBetaVersion(), pe.version.getAlphaBetaVersion());
		Assert.assertEquals(version.getBuildNumber(), pe.version.getBuildNumber());
		Assert.assertEquals(version.getMajor(), pe.version.getMajor());
		Assert.assertEquals(version.getMinor(), pe.version.getMinor());
		Assert.assertEquals(version.getProgramName(), pe.version.getProgramName());
		Assert.assertEquals(version.getRevision(), pe.version.getRevision());
		Assert.assertEquals(version.getProjectEndDate(), pe.version.getProjectEndDate());
		Assert.assertEquals(version.getProjectStartDate(), pe.version.getProjectStartDate());
		Assert.assertEquals(version.getType(), pe.version.getType());
		Assert.assertEquals(version.getDevelopers(), pe.version.getDevelopers());
		Assert.assertEquals(version.getCreators(), pe.version.getCreators());
		Assert.assertEquals(version.getDescriptions(), pe.version.getDescriptions());
	    }
	    return true;
	}
	else
	    return false;
    }
    public static boolean equals(Object o1, Object o2)
    {
	if (o1==o2)
	    return true;
	if (o1==null)
	    return false;
	Assert.assertEquals(o2, o1);
	return o1.equals(o2);
    }
    
    

}

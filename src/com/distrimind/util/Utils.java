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
package com.distrimind.util;

import java.io.InputStream;
import java.util.Calendar;

import com.distrimind.util.export.License;
import com.distrimind.util.version.Description;
import com.distrimind.util.version.Person;
import com.distrimind.util.version.PersonDeveloper;
import com.distrimind.util.version.Version;

/**
 * 
 * @author Jason Mahdjoub
 * @version 1.6
 */
public class Utils
{
    public static final Version VERSION;
    public static final License LICENSE=new License(License.PredefinedLicense.CeCILL_C_v1_0);
    static
    {
	Calendar c=Calendar.getInstance();
	c.set(2016, 1, 4);
	Calendar c2=Calendar.getInstance();
	c.set(2016, 11, 6);
    	VERSION=new Version("Utils", "Utils", 1,9,0, Version.Type.Stable, 0, c.getTime(), c2.getTime());
	try
	{
	
	    InputStream is=Utils.class.getResourceAsStream("build.txt");
	    VERSION.loadBuildNumber(is);
	
	    VERSION.addCreator(new Person("mahdjoub", "jason"));
	    c=Calendar.getInstance();
	    c.set(2016, 1, 4);
	    VERSION.addDeveloper(new PersonDeveloper("mahdjoub", "jason", c.getTime()));
	
	    c=Calendar.getInstance();
	    c.set(2016, 11, 6);
	    Description d=new Description(1,8,0,Version.Type.Stable, 0, c.getTime());
	    d.addItem("Correcting a bug with the use of IV parameter. Now, the IV parameter is generated for each encryption.");
	    d.addItem("Adding class SecureRandomType.");

	    c=Calendar.getInstance();
	    c.set(2016, 9, 13);
	    d=new Description(1,8,0,Version.Type.Stable, 0, c.getTime());
	    d.addItem("Adding password hash (PBKDF and bcrypt)");

	    c=Calendar.getInstance();
	    c.set(2016, 8, 15);
	    d=new Description(1,7,2,Version.Type.Stable, 0, c.getTime());
	    d.addItem("Correcting a bug for P2PASymmetricSecretMessageExchanger");
	    d.addItem("Adding toString and valueOf functions for crypto keys");
	    d.addItem("Possibility to put crypto keys in XMLProperties class");
	    d.addItem("Adding 'valueOf' for Decentralized IDs");
	    d.addItem("Decentralized IDs are exportable into XML Properties");

	    c=Calendar.getInstance();
	    c.set(2016, 7, 23);
	    d=new Description(1,7,1,Version.Type.Stable, 0, c.getTime());
	    d.addItem("Correcting a bug for loop back network interface speed");
	    d.addItem("Correcting a bug for P2PASymmetricSecretMessageExchanger");
	    d.addItem("Correcting a bug big data asymmetric encryption");
	    d.addItem("Adding symmetric et asymmetric keys encapsulation");

	    c=Calendar.getInstance();
	    c.set(2016, 6, 4);
	    d=new Description(1,7,0,Version.Type.Stable, 0, c.getTime());
	    d.addItem("Renaming class ASymmetricEncryptionAlgorithm to P2PASymmetricEncryptionAlgorithm");
	    d.addItem("Adding class SignatureCheckerAlgorithm");
	    d.addItem("Adding class SignerAlgorithm");
	    d.addItem("Adding class ClientASymmetricEncryptionAlgorithm");
	    d.addItem("Adding class ServerASymmetricEncryptionAlgorithm");
	    d.addItem("Updating to Common-Net 3.5");

	    c=Calendar.getInstance();
	    c.set(2016, 5, 10);
	    d=new Description(1,6,1,Version.Type.Stable, 0, c.getTime());
	    d.addItem("Correcting bug into XMLProperties class");
	    d.addItem("Adding tests for XMLProperties class");
	    d.addItem("Changing license to CECILL-C.");
	    d.addItem("Correcting bugs into DecentralizedIDGenerator classes");
	    d.addItem("Adding salt management into SecuredIDGenerator class");
	    d.addItem("Adding salt management into PeerToPeerASymetricSecretMessageExanger class");

	    c=Calendar.getInstance();
	    c.set(2016, 2, 15);
	    d=new Description(1,6,0,Version.Type.Stable, 0, c.getTime());
	    d.addItem("Adding unit tests possibility for project export tools");
	    d.addItem("Adding unit compilation for project export tools");
	    d.addItem("Adding new licences");

	    c=Calendar.getInstance();
	    c.set(2016, 2, 9);
	    d=new Description(1,5,0,Version.Type.Stable, 0, c.getTime());
	    d.addItem("Adding PeerToPeerASymmetricSecretMessageExchanger class");
	    d.addItem("Adding ObjectSizer class (determins sizeof each java object instance)");
	    d.addItem("Adding keys encoding");
	    d.addItem("Adding decentralized id encoding/decoding");
	    VERSION.addDescription(d);

	    c=Calendar.getInstance();
	    c.set(2016, 2, 1);
	    d=new Description(1,4,0,Version.Type.Stable, 0, c.getTime());
	    d.addItem("Adding encryption utilities");
	    VERSION.addDescription(d);

	    c=Calendar.getInstance();
	    c.set(2016, 1, 24);
	    d=new Description(1,3,1,Version.Type.Stable, 0, c.getTime());
	    d.addItem("Set Bits static functions public");
	    VERSION.addDescription(d);

	    c=Calendar.getInstance();
	    c.set(2016, 1, 22);
	    d=new Description(1,3,0,Version.Type.Stable, 0, c.getTime());
	    d.addItem("Adding SecuredDecentralizedID class");
	    VERSION.addDescription(d);

	    c=Calendar.getInstance();
	    c.set(2016, 1, 15);
	    d=new Description(1,2,0,Version.Type.Stable, 0, c.getTime());
	    d.addItem("Adding function AbstractXMLObjectParser.isValid(Class)");
	    d.addItem("Correcting export bug : temporary files were not deleted.");
	    VERSION.addDescription(d);
	    
	    c=Calendar.getInstance();
	    c.set(2016, 1, 14);
	    d=new Description(1,1,0,Version.Type.Stable, 0, c.getTime());
	    d.addItem("Adding some internal modifications to ReadWriteLocker");
	    VERSION.addDescription(d);

	    c=Calendar.getInstance();
	    c.set(2016, 1, 4);
	    d=new Description(1,0,0,Version.Type.Stable, 0, c.getTime());
	    d.addItem("Realeasing first version of Utils");
	    VERSION.addDescription(d);
	}
	catch(Exception e)
	{
	    e.printStackTrace();
	}
    }
    
}

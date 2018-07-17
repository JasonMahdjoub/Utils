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

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

import static com.distrimind.util.OSVersion.getCurrentOSVersion;

/**
 * Set of functions giving information about the current running OS
 * 
 * @author Jason Mahdjoub
 * @version 2.2
 * @since Utils 1.0
 *
 */
public enum OS {
	LINUX("(linux)|(x11)"),
    OPEN_BSD("(openbsd)"),
    SUN_OS("sunos"),
    BEOS("beos"),
    QNX("qnx"),
    IOS("(iphone)|(ipad)"),
	MAC_OS(".*mac.*"),
    OS_2("os/2"),
	WINDOWS(".*win.*"),
	ANDROID("(android)"),
    SEARCH_BOT("(nuhk)|(googlebot)|(yammybot)|(openbot)|(slurp)|(mnsbot)|(ssk jeeves/teoma)");

	final Pattern pattern;

	OS(String regex)
	{
		this.pattern = Pattern.compile(regex);
	}

	@SuppressWarnings("unused")
    public static OS getFrom(String userAgent) {
		for (OS os : OS.values()) {
			if (os.pattern.matcher(userAgent.toLowerCase()).matches())
				return os;
		}
		return null;
	}

	static String OSName = System.getProperty("os.name").toLowerCase();


	

	
	private static final double currentJREVersion;
	static
	{
		double d;
		try
		{
			d=Double.parseDouble(System.getProperty("java.specification.version"));
		}
		catch(Throwable t)
		{
			d=0.0;
		}
		
		currentJREVersion=d;
	}

	public static double getCurrentJREVersionDouble()
	{
		return currentJREVersion;
	}
	public static byte getCurrentJREVersionByte()
	{
		return (byte)(currentJREVersion-1.0*10.0);
	}
	


    @SuppressWarnings("unused")
    public boolean isUnix() {

        return (OSName.contains("nix") || OSName.contains("nux") || OSName.indexOf("aix") > 0);

    }




	static boolean isAndroid()
	{
		try {
			return Class.forName("android.os.Build.VERSION")!=null;
		} catch (ClassNotFoundException e) {
			return false;
		}
	}
	

	
	public static String getJVMLocation()
	{
		if (getCurrentOSVersion()!=null && getCurrentOSVersion().getOS()==WINDOWS) {
		    return System.getProperties().getProperty("java.home") + File.separator + "bin" + File.separator + "java.exe";
		} 
		else if (isAndroid())
			return "java";
		else {
		    return System.getProperties().getProperty("java.home") + File.separator + "bin" + File.separator + "java";
		}
	}
	
	private static volatile Boolean aesNIAcceleration=null;
	
	public static boolean supportAESIntrinsicsAcceleration() 
	{
		if (aesNIAcceleration==null)
		{
			try
			{
				Process p=Runtime.getRuntime().exec(getJVMLocation()+" -XX:+PrintFlagsFinal -version");
				
				try(InputStream is=p.getInputStream();InputStreamReader isr=new InputStreamReader(is); BufferedReader br=new BufferedReader(isr))
				{
					String line=br.readLine();
					while (line!=null)
					{
						line=line.toLowerCase();
						if (line.contains("useaesintrinsics"))
						{
							aesNIAcceleration= line.contains("true");
						}
						line=br.readLine();
					}
				}
				p.destroy();
			}
			catch(IOException e)
			{
				e.printStackTrace();
			}
			if (aesNIAcceleration==null)
				aesNIAcceleration= Boolean.FALSE;
		}
		return aesNIAcceleration;
		
	}

	@SuppressWarnings("unused")
    public boolean SIPrefixAreUnderstoodAsBinaryPrefixForByteMultiples()
	{
		return this == WINDOWS || (this == MAC_OS && Double.valueOf(OSVersion.OS_VERSION) < 10.1);
	}

	@SuppressWarnings("unused")
    List<OSVersion> getVersions()
    {
        List<OSVersion> res=new ArrayList<>();
        for (OSVersion v : OSVersion.values())
            if (v.getOS()==this)
                res.add(v);
        return res;
    }
}

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


/**
 * Set of functions giving information about the current running OS
 * 
 * @author Jason Mahdjoub
 * @version 2.1
 * @since Utils 1.0
 *
 */
public enum OSValidator {
	UNKNOW,
	LINUX,
	MACOS,
	SOLARIS,
	WINDOWS,
	ANDROID;
	
	private static String OS = System.getProperty("os.name").toLowerCase();

	private static String OS_VERSION = System.getProperty("os.name") + " " + System.getProperty("os.version");
	
	static private volatile OSValidator currentOS=null;
	
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
	
	public static OSValidator getCurrentOS()
	{
		if (currentOS==null)
		{
			if (isLinux())
				currentOS=LINUX;
			else if (isMac())
				currentOS=OSValidator.MACOS;
			else if (isSolaris())
				currentOS=OSValidator.SOLARIS;
			else if (isWindows())
				currentOS=OSValidator.WINDOWS;
			else if (isAndroid())
				currentOS=OSValidator.ANDROID;
			else
				currentOS=UNKNOW;
		}
		return currentOS;
	}
	
	
	public String getOSVersion() {
		return OS_VERSION;
	}

	private static boolean isLinux() {

		return OS.indexOf("linux") >= 0;
	}

	private static boolean isMac() {
		return (OS.indexOf("mac") >= 0);

	}

	private static boolean isSolaris() {

		return (OS.indexOf("sunos") >= 0);

	}

	public boolean isUnix() {

		return (OS.indexOf("nix") >= 0 || OS.indexOf("nux") >= 0 || OS.indexOf("aix") > 0);

	}

	private static boolean isWindows() {

		return (OS.indexOf("win") >= 0);
	}

	private static boolean isAndroid()
	{
		try {
			return Class.forName("android.os.Build.VERSION")!=null;
		} catch (ClassNotFoundException e) {
			return false;
		}
	}
	
	public String getAndroidVersion()
	{
		try {
			Class<?> versionClass=Class.forName("android.os.Build.VERSION");
			return (String)versionClass.getDeclaredField("RELEASE").get(null);
		} catch (ClassNotFoundException | IllegalArgumentException | IllegalAccessException | NoSuchFieldException | SecurityException e) {
			return null;
		}
	}
	
	
}

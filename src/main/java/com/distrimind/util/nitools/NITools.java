/*
Copyright or © or Corp. Jason Mahdjoub (04/02/2016)

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

package com.distrimind.util.nitools;

import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.Enumeration;
import java.util.concurrent.atomic.AtomicReference;

import com.distrimind.util.systeminfo.OS;
import com.distrimind.util.systeminfo.OSVersion;

/**
 * Class that gives tools for network interfaces, independently of current OS
 * running.
 * 
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 1.0
 * 
 */
public abstract class NITools {
	private static final AtomicReference<NITools> instance = new AtomicReference<>();

	/**
	 * 
	 * @return a unique instance of TraceRoute
	 */
	public static NITools getInstance() {
		if (instance.get() == null) {
			synchronized (instance) {
				if (instance.get() == null) {
					if (OSVersion.getCurrentOSVersion()!=null && OSVersion.getCurrentOSVersion().getOS()==OS.LINUX)
						instance.set(new LinuxNITools());
					else if (OSVersion.getCurrentOSVersion()!=null && OSVersion.getCurrentOSVersion().getOS()==OS.WINDOWS
							&& !OSVersion.WINDOWS_XP.getLowerOrEqualsVersions().contains(OSVersion.getCurrentOSVersion()))
						instance.set(new WindowsNITools());// TODO see for
					// Windows XP
					// compatibility
					else if (OSVersion.getCurrentOSVersion()!=null && OSVersion.getCurrentOSVersion().getOS()==OS.MAC_OS_X)
						instance.set(new MacOSXNITools());
					else
						instance.set(new DefaultNITools());
				}
			}
		}
		return instance.get();
	}

	public static void main(String[] args) throws SocketException {
		Enumeration<NetworkInterface> e = NetworkInterface.getNetworkInterfaces();
		while (e.hasMoreElements()) {
			NetworkInterface ni = e.nextElement();
			System.out.print(ni.getName() + " : ");
			System.out.println(getInstance().getNetworkInterfaceSpeed(ni));
		}

	}

	NITools() {

	}

	/**
	 * Gets the speed in bytes of the given network interface
	 * 
	 * @param network_interface
	 *            the network interface to test
	 * @return the speed in byte of the given network interface or -1 if the speed
	 *         couldn't be got.
	 */
	public abstract long getNetworkInterfaceSpeed(NetworkInterface network_interface);

	long readLong(String value) {
		String substring = value.substring(0, value.length() - 4);
		if (value.toLowerCase().endsWith("kb/s")) {
			return Long.parseLong(substring) * 1000L;
		} else if (value.toLowerCase().endsWith("mb/s")) {
			return Long.parseLong(substring) * 1000000L;
		} else if (value.toLowerCase().endsWith("gb/s")) {
			return Long.parseLong(substring) * 1000000000L;
		} else if (value.toLowerCase().endsWith("tb/s")) {
			return Long.parseLong(substring) * 1000000000000L;
		} else
			return Long.parseLong(value);
	}

}

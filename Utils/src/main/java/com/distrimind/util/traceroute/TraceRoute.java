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

package com.distrimind.util.traceroute;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import com.distrimind.util.OSValidator;

/**
 * Class that enables a trace route considering an {@link InetAddress},
 * independently from current OS running.
 * 
 * @author Jason Mahdjoub
 * @version 1.0
 * @since MadKitLanEdition 1.0
 * 
 */
public abstract class TraceRoute {

	private static final AtomicReference<TraceRoute> instance = new AtomicReference<>();

	/**
	 * 
	 * @return a unique instance of TraceRoute
	 */
	public static TraceRoute getInstance() {
		if (instance.get() == null) {
			synchronized (instance) {
				if (instance.get() == null) {
					if (OSValidator.getCurrentOS()==OSValidator.LINUX)
						instance.set(new LinuxTraceRoute());
					else if (OSValidator.getCurrentOS()==OSValidator.WINDOWS)
						instance.set(new WindowsTraceRoute());
					else if (OSValidator.getCurrentOS()==OSValidator.MACOS)
						instance.set(new MacOSTraceRoute());
					else
						instance.set(new DefaultTraceRoute());
				}
			}
		}
		return instance.get();
	}

	public static void main(String args[]) throws UnknownHostException {
		for (InetAddress ia : getInstance().tracePath(InetAddress.getByName("192.168.0.14"), -1, -1))
			System.out.println(ia);

	}

	TraceRoute() {

	}

	/**
	 * Tracks the route packets taken from an IP network on their way to a given
	 * {@link InetAddress}.
	 * 
	 * @param _ia
	 *            the host name to trace
	 * @return a ordered list of {@link InetAddress} (the route packet).
	 */
	public List<InetAddress> tracePath(InetAddress _ia) {
		return this.tracePath(_ia, -1, -1);
	}

	/**
	 * Tracks the route packets taken from an IP network on their way to a given
	 * {@link InetAddress}.
	 * 
	 * @param _ia
	 *            the host name to trace
	 * @param depth
	 *            Specifies the maximum number of hops
	 * @return a ordered list of {@link InetAddress} (the route packet).
	 */
	public List<InetAddress> tracePath(InetAddress _ia, int depth) {
		return this.tracePath(_ia, depth, -1);
	}

	/**
	 * Tracks the route packets taken from an IP network on their way to a given
	 * {@link InetAddress}.
	 * 
	 * @param _ia
	 *            the host name to trace
	 * @param depth
	 *            Specifies the maximum number of hops
	 * @param time_out_ms
	 *            Set the time (in milliseconds) to wait for a response to a probe.
	 * @return a ordered list of {@link InetAddress} (the route packet). Some
	 *         elements can be <code>null</code> references if no reply was given by
	 *         some servers.
	 */
	public abstract List<InetAddress> tracePath(InetAddress _ia, int depth, int time_out_ms);

}

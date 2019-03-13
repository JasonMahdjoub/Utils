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

import com.distrimind.util.Utils;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * 
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 1.0
 * @see TraceRoute
 */
class WindowsTraceRoute extends TraceRoute {
	WindowsTraceRoute() {

	}

	@Override
	public List<InetAddress> tracePath(InetAddress _ia, int depth, int time_out_ms) {
		try {
			ArrayList<InetAddress> res = new ArrayList<>();
			if (depth > 0)
				++depth;
			Process p = Runtime.getRuntime().exec("tracert -d " + (depth < 0 ? "" : ("-h " + depth + " "))
					+ (time_out_ms < 0 ? "" : ("-w " + (time_out_ms) + " ")) + _ia.getHostAddress());

			try (InputStreamReader isr = new InputStreamReader(p.getInputStream())) {
				try (BufferedReader input = new BufferedReader(isr)) {
					String line ;

					Pattern pattern = Pattern.compile("^[1-9][0-9]*");

					while ((line = input.readLine()) != null) {
						String[] split = line.split(" ");
						String first_string = null;
						for (String aSplit : split) {
							if (aSplit.length() > 0) {
								first_string = aSplit;
								break;
							}
						}

						assert first_string != null;
						if (split.length > 3 && pattern.matcher(first_string).matches()) {
							try {
								res.add(InetAddress.getByName(split[split.length - 1]));
							} catch (Exception e) {
								res.add(null);
							}
						}
					}
				}
			}
			finally {
				Utils.flushAndDestroyProcess(p);
			}
			return res;

		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}

}

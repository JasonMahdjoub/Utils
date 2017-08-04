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

package com.distrimind.util.harddrive;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;

/**
 * 
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 1.0
 * @see HardDriveDetect
 */
class MacOSHardDriveDetect extends UnixHardDriveDetect {

	@Override
	long getTimeBeforeUpdate() {
		return 30000;
	}

	@Override
	Partition scanPartitions() {
		Partition root = new Partition();
		try {
			Process p = Runtime.getRuntime().exec("diskutil list");
			try (InputStreamReader isr = new InputStreamReader(p.getInputStream())) {
				try (BufferedReader input = new BufferedReader(isr)) {
					String current_drive = null;
					String line;

					while ((line = input.readLine()) != null) {
						if (line.startsWith("/dev/")) {
							if (new File(line).exists())
								current_drive = line;
							else
								current_drive = null;
						} else if (current_drive != null) {
							String strings[] = line.split(" ");
							if (strings.length > 0) {
								String lastString = strings[strings.length - 1];
								int lastindex = lastString.lastIndexOf("s");
								String part = "s";
								if (lastindex > 0) {
									boolean ok = true;
									for (int i = lastindex + 1; i < lastString.length(); i++) {
										char c = lastString.charAt(i);
										part += c;
										if (c < '0' || c > '9') {
											ok = false;
										}
									}
									if (ok) {
										String currentPart = current_drive + part;
										Process p2 = Runtime.getRuntime().exec("diskutil info " + currentPart);
										try (InputStreamReader isr2 = new InputStreamReader(p2.getInputStream())) {
											try (BufferedReader input2 = new BufferedReader(isr2)) {
												String line2;
												boolean mounted = false;

												while ((line2 = input2.readLine()) != null) {
													strings = line2.split(" ");
													String s1 = null;
													String s2 = null;
													String s3 = null;
													for (int i = 0; i < strings.length; i++) {
														if (strings[i].length() != 0) {
															if (s1 == null)
																s1 = strings[i];
															else if (s2 == null) {
																s2 = strings[i];
																if (!mounted)
																	break;
															} else if (s3 == null) {
																s3 = strings[i];
																break;
															}
														}
													}
													if (s2 != null) {
														if (s1.startsWith("Mounted")) {
															if (s2.equals("Yes")) {
																mounted = true;
															} else
																break;
														} else if (mounted && s3 != null && s1.equals("Mount")
																&& s2.startsWith("Point")) {
															try {
																File mount = new File(s3);
																if (mount.exists()) {
																	Partition partition = new Partition(
																			new File(current_drive), mount);
																	root.addPartition(partition);
																}
															} catch (Exception e) {
															}
															break;
														}
													}
												}
											}
										}
									}
								}
							}
						}
					}
				}
			}
			p.destroy();
			return root;
		} catch (Exception e) {
			return new Partition();
		}
	}

}

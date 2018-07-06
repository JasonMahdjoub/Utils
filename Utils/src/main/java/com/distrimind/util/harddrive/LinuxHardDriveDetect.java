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
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;

/**
 * 
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 1.0
 * @see HardDriveDetect
 */

class LinuxHardDriveDetect extends UnixHardDriveDetect {
	LinuxHardDriveDetect() {

	}


	@Override
	UnixPartition scanPartitions() {
		return scanPartitions(2);
	}

	UnixPartition scanPartitions(int iteration) {
		UnixPartition root = new UnixPartition();
		if (iteration <= 0)
			return root;

		File file = new File("/proc/mounts");
		try (FileInputStream fis = new FileInputStream(file)) {
			try (InputStreamReader isr = new InputStreamReader(fis)) {
				try (BufferedReader br = new BufferedReader(isr)) {
					String line = br.readLine();
					while (line != null) {
						String values[] = line.split(" ");
						if (values.length > 1) {
							String id = values[0];
							if (id.startsWith("/dev/")) {
								try {
									id = new File(id).getCanonicalPath();
									char last_char = id.charAt(id.length() - 1);
									while (last_char >= '0' && last_char <= '9') {
										id = id.substring(0, id.length() - 1);
										if (id.length() > 0) {
											last_char = id.charAt(id.length() - 1);
										} else
											break;
									}
									if (id.length() > 1) {
										try {
											UnixPartition p = new UnixPartition(new File(id), new File(values[1]));
											root.addPartition(p);
										} catch (Exception e) {
										}
									}
								} catch (IOException e) {
								}
							} else {
								try {
									UnixPartition p = new UnixPartition(new File(values[1]));
									root.addPartition(p);
								} catch (Exception e) {
								}
							}
						}
						line = br.readLine();
					}
				}
			}
		} catch (FileNotFoundException e) {
		} catch (IOException e) {
			return scanPartitions(--iteration);
		}
		return root;
	}

}

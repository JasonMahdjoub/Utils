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
import java.io.FileWriter;
import java.io.InputStreamReader;
import java.util.HashMap;

/**
 * 
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 1.0
 * @see HardDriveDetect
 */
class WindowsHardDriveDetect extends HardDriveDetect {

	private static class Identifier {
		public final String identifier;

		private final long timeToBeUpdated;

		public Identifier(String _identifier) {
			identifier = _identifier;
			timeToBeUpdated = System.currentTimeMillis() + duration_between_each_update;
		}

		public boolean hasToBeUpdated() {
			return System.currentTimeMillis() - timeToBeUpdated > 0;
		}
	}

	private static final long duration_between_each_update = 10000;

	private HashMap<Character, Identifier> identifiers = new HashMap<>();

	@Override
	public String getHardDriveIdentifier(File _file) {
		synchronized (identifiers) {
			try {
				char drive = _file.getCanonicalPath().charAt(0);
				if (drive >= 'A' && drive <= 'Z')
					drive = (char) (drive - ('A' - 'a'));
				if (!((drive >= 'a' && drive <= 'z') || (drive >= 'A' || drive <= 'Z')))
					return HardDriveDetect.DEFAULT_HARD_DRIVE_IDENTIFIER;
				Character Drive = Character.valueOf(drive);
				Identifier id = identifiers.get(Drive);
				if (id == null) {
					id = getIdentifier(drive);
					identifiers.put(Drive, id);
				} else if (id.hasToBeUpdated()) {
					id = getIdentifier(drive);
					identifiers.put(Drive, id);
				}
				return id.identifier;
			} catch (Exception e) {
				return HardDriveDetect.DEFAULT_HARD_DRIVE_IDENTIFIER;
			}
		}
	}

	private Identifier getIdentifier(char drive) {

		try {
			String result = "";
			File file = File.createTempFile("realhowto", ".vbs");
			file.deleteOnExit();
			try (FileWriter fw = new java.io.FileWriter(file)) {
				String vbs = "Set objFSO = CreateObject(\"Scripting.FileSystemObject\")\n"
						+ "Set colDrives = objFSO.Drives\n" + "Set objDrive = colDrives.item(\"" + drive + "\")\n"
						+ "Wscript.Echo objDrive.SerialNumber";
				fw.write(vbs);
			}
			Process p = Runtime.getRuntime().exec("cscript //NoLogo " + file.getPath());
			try (InputStreamReader isr = new InputStreamReader(p.getInputStream())) {
				try (BufferedReader input = new BufferedReader(isr)) {
					String line;
					while ((line = input.readLine()) != null) {
						result += line;
					}

				}
			}
			p.destroy();
			if (result.length() == 0)
				return new Identifier(HardDriveDetect.DEFAULT_HARD_DRIVE_IDENTIFIER);
			return new Identifier(result.trim());
		} catch (Exception e) {
			return new Identifier(HardDriveDetect.DEFAULT_HARD_DRIVE_IDENTIFIER);
		}
	}

}

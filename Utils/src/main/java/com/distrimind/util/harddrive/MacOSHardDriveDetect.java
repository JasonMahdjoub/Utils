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

import com.distrimind.util.properties.MultiFormatProperties;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.xml.sax.SAXException;

import javax.xml.parsers.ParserConfigurationException;
import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

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
	List<Partition> scanPartitions() throws IOException {
		//UnixPartition root = new UnixPartition();
		try {
			List<Partition> res = new ArrayList<>();
			Process p = Runtime.getRuntime().exec("diskutil list -plist");
			ArrayList<String> partitionIdentifiers = new ArrayList<>();
			Document d = MultiFormatProperties.getDOM(p.getInputStream());
			Node rootNode = null;
			for (int i = 0; i < d.getChildNodes().getLength(); i++) {
				Node n = d.getChildNodes().item(i);
				if (n.getNodeName().equals("dict")) {
					rootNode = n;
					break;
				}
			}
			if (rootNode == null)
				return res;
			boolean takeNext = false;

			for (int i = 0; i < rootNode.getChildNodes().getLength(); i++) {
				Node n = rootNode.getChildNodes().item(i);
				if (takeNext && n.getNodeName().equals(("array"))) {
					for (int j = 0; j < n.getChildNodes().getLength(); j++) {
						Node disk = n.getChildNodes().item(j);
						if (disk.getNodeName().equals("string"))
							partitionIdentifiers.add(disk.getNodeValue());
					}
					break;
				} else if (n.getNodeName().equals(("key")) && n.getNodeValue().equals("AllDisks")) {
					takeNext = true;
				} else
					takeNext = false;
			}
			p.destroy();

			for (String partitionIdentifier : partitionIdentifiers) {
				Process p2 = Runtime.getRuntime().exec("diskutil info -plist " + partitionIdentifier);
				d = MultiFormatProperties.getDOM(p2.getInputStream());

				for (int i = 0; i < d.getChildNodes().getLength(); i++) {
					Node n = d.getChildNodes().item(i);

					if (n.getNodeName().equals("dict")) {
						String currentKey = null;

						String deviceIdentifier = null, mountPoint = null, volumeName = null, content = null,
								deviceNode = null, fileSystemName = null, fileSystemType = null, protocol = null;
						boolean removable = true, writable = false;
						long size = -1, freeSpace = -1;
						int volumeBlockSize = 1;
						UUID volumeUUID = null;

						for (int j = 0; j < n.getChildNodes().getLength(); j++) {
							Node descN = n.getChildNodes().item(j);
							if (descN.getNodeName().equals("key")) {
								currentKey = descN.getNodeValue();
							} else if (currentKey != null) {
								switch (currentKey) {
									case "Content":
										if (descN.getNodeName().equals("string"))
											content = descN.getNodeValue();
										break;
									case "VolumeAllocationBlockSize":
										if (descN.getNodeName().equals("integer")) {
											try {
												volumeBlockSize = Integer.valueOf(descN.getNodeValue());
											} catch (Exception e) {
												volumeBlockSize = -1;
											}
										}
										break;

									case "DeviceIdentifier":
										if (descN.getNodeName().equals("string"))
											deviceIdentifier = descN.getNodeValue();
										break;
									case "DeviceNode":
										if (descN.getNodeName().equals("string"))
											deviceNode = descN.getNodeValue();
										break;
									case "RemovableMediaOrExternalDevice":
										removable = descN.getNodeName().equals("true");

										break;
									case "FilesystemUserVisibleName":
										if (descN.getNodeName().equals("string"))
											fileSystemName = descN.getNodeValue();
										break;
									case "FilesystemType":
										if (descN.getNodeName().equals("string"))
											fileSystemType = descN.getNodeValue();
										break;
									case "FreeSpace":
										try {
											if (descN.getNodeName().equals("integer"))
												freeSpace = Long.valueOf(descN.getNodeValue());
										} catch (Exception e) {
											freeSpace = -1;
										}
										break;
									case "MountPoint":
										if (descN.getNodeName().equals("String"))
											mountPoint = descN.getNodeValue();
										break;
									case "Size":
										try {
											if (descN.getNodeName().equals("integer"))
												size = Long.valueOf(descN.getNodeValue());
										} catch (Exception e) {
											size = -1;
										}
										break;
									case "VolumeName":
										if (descN.getNodeName().equals("string"))
											volumeName = descN.getNodeValue();
										break;
									case "VolumeUUID":
										if (descN.getNodeName().equals("string"))
											volumeUUID = UUID.fromString(descN.getNodeValue());
										break;
									case "Writable":
										writable = descN.getNodeName().equals("true");

										break;
									case "BusProtocol":
										if (descN.getNodeName().equals("string"))
											protocol = descN.getNodeValue();

										break;
								}
							}
						}
						if (deviceIdentifier != null && mountPoint != null && volumeName != null && volumeUUID != null) {
							Partition partition = new Partition(volumeUUID, new File(mountPoint), deviceIdentifier, fileSystemType, fileSystemName, volumeBlockSize, writable, removable, volumeName, protocol, size);
							res.add(partition);
						}
						break;
					}
				}

				p2.destroy();
			}


			return res;
		}
		catch(ParserConfigurationException | SAXException e)
		{
			throw new IOException(e);
		}


	}

}

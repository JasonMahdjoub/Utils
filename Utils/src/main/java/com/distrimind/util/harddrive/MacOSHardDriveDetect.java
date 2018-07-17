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
import java.io.File;
import java.io.IOException;
import java.util.*;

/**
 * 
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 1.0
 * @see HardDriveDetect
 */
class MacOSHardDriveDetect extends UnixHardDriveDetect {

    private HashSet<Disk> disks;
    private HashSet<Partition> partitions;




	@Override
    Set<Disk> getDetectedDisksImpl() {
        return disks;
    }

    @Override
    Set<Partition> getDetectedPartitionsImpl() {
        return partitions;
    }

    @SuppressWarnings("ConstantConditions")
	@Override
	void scanDisksAndPartitions() throws IOException {

		try {
            disks=new HashSet<>();
            partitions=new HashSet<>();

			Process p = Runtime.getRuntime().exec("diskutil list -plist");

			ArrayList<String> partitionIdentifiers = new ArrayList<>();
			Document d = MultiFormatProperties.getDOM(p.getInputStream());
			Node rootNode = null;
			for (int i = 0; i < d.getChildNodes().getLength(); i++) {
				Node n = d.getChildNodes().item(i);
                if (n.getNodeType()!=Node.ELEMENT_NODE)
                    continue;

                if (n.getNodeName().equals("plist") && n.hasAttributes() && n.getAttributes().getNamedItem("version")!=null) {
					rootNode = n;
					break;
				}
			}
			if (rootNode == null)
				return;
			Node rn2=null;
            for (int i = 0; i < rootNode.getChildNodes().getLength(); i++) {
                Node n = rootNode.getChildNodes().item(i);
                if (n.getNodeType()!=Node.ELEMENT_NODE)
                    continue;

                if (n.getNodeName().equals("dict")) {
                    rn2 = n;
                    break;
                }
            }
            if (rn2==null)
                return;
            rootNode=rn2;
			boolean takeNext = false;

			for (int i = 0; i < rootNode.getChildNodes().getLength(); i++) {
				Node n = rootNode.getChildNodes().item(i);
                if (n.getNodeType()!=Node.ELEMENT_NODE)
                    continue;
				if (takeNext && n.getNodeName().equals("array")) {
					for (int j = 0; j < n.getChildNodes().getLength(); j++) {
						Node disk = n.getChildNodes().item(j);
                        if (disk.getNodeType()!=Node.ELEMENT_NODE)
                            continue;

                        if (disk.getNodeName().equals("string") && disk.getTextContent()!=null)
							partitionIdentifiers.add(disk.getTextContent());
					}
					break;
				} else takeNext = n.getNodeName().equals("key") && "AllDisks".equals(n.getTextContent());
			}
			p.destroy();
			for (String partitionIdentifier : partitionIdentifiers) {
				Process p2 = Runtime.getRuntime().exec("diskutil info -plist " + partitionIdentifier);
				d = MultiFormatProperties.getDOM(p2.getInputStream());
                rootNode=null;
				for (int i = 0; i < d.getChildNodes().getLength(); i++) {
                    Node n = d.getChildNodes().item(i);
                    if (n.getNodeType()!=Node.ELEMENT_NODE)
                        continue;
                    if (n.getNodeName().equals("plist") && n.hasAttributes() && n.getAttributes().getNamedItem("version")!=null) {
                        rootNode = n;
                        break;
                    }
                }
                if (rootNode==null)
                    continue;
				for (int i = 0; i < rootNode.getChildNodes().getLength(); i++) {
					Node n = rootNode.getChildNodes().item(i);
                    if (n.getNodeType()!=Node.ELEMENT_NODE)
                        continue;
					if (n.getNodeName().equals("dict")) {
						String currentKey = null;

						String deviceIdentifier = null, mountPoint = null, volumeName = null,
								deviceNode = null, fileSystemName = null, fileSystemType = null, protocol = null, mediaName=null;
						boolean internal = false, writable = false;
						long size = -1, diskSize=-1;
						int volumeBlockSize = 1, deviceBlockSize=-1;
						UUID volumeUUID = null, diskUUID=null;

						for (int j = 0; j < n.getChildNodes().getLength(); j++) {
							Node descN = n.getChildNodes().item(j);
                            if (descN.getNodeType()!=Node.ELEMENT_NODE)
                                continue;
							if (descN.getNodeName().equals("key")) {
								currentKey = descN.getTextContent();
							} else if (currentKey != null) {
								switch (currentKey) {

									case "VolumeAllocationBlockSize":
										if (descN.getNodeName().equals("integer")) {
											try {
												volumeBlockSize = Integer.valueOf(descN.getTextContent());
											} catch (Exception e) {
												volumeBlockSize = -1;
											}
										}
										break;
                                    case "DeviceBlockSize":
                                        if (descN.getNodeName().equals("integer")) {
                                            try {
                                                deviceBlockSize = Integer.valueOf(descN.getTextContent());
                                            } catch (Exception e) {
                                                deviceBlockSize = -1;
                                            }
                                        }
                                        break;
									case "DeviceIdentifier":
										if (descN.getNodeName().equals("string"))
											deviceIdentifier = descN.getTextContent();
										break;
									case "DeviceNode":
										if (descN.getNodeName().equals("string"))
											deviceNode = descN.getTextContent();
										break;
									case "Internal":
										internal = descN.getNodeName().equals("true");

										break;
									case "FilesystemUserVisibleName":
										if (descN.getNodeName().equals("string"))
											fileSystemName = descN.getTextContent();
										break;
									case "FilesystemType":
										if (descN.getNodeName().equals("string"))
											fileSystemType = descN.getTextContent();
										break;
                                    case "MediaName":
                                        if (descN.getNodeName().equals("string"))
                                            mediaName = descN.getTextContent();
                                        break;
								
									case "MountPoint":
										if (descN.getNodeName().equals("string"))
											mountPoint = descN.getTextContent();
										if ("".equals(mountPoint))
										    mountPoint=null;
										break;
									case "Size":
										try {
											if (descN.getNodeName().equals("integer"))
												diskSize = Long.valueOf(descN.getTextContent());
										} catch (Exception e) {
                                            diskSize = -1;
										}
										break;
                                    case "VolumeSize":
                                        try {
                                            if (descN.getNodeName().equals("integer"))
                                                size = Long.valueOf(descN.getTextContent());
                                        } catch (Exception e) {
                                            size = -1;
                                        }
                                        break;
									case "VolumeName":
										if (descN.getNodeName().equals("string"))
											volumeName = descN.getTextContent();
										break;
									case "VolumeUUID":
									    try {
                                            if (descN.getNodeName().equals("string"))
                                                volumeUUID = UUID.fromString(descN.getTextContent());
                                        }
                                        catch(Exception e)
                                        {
                                            e.printStackTrace();
                                        }

                                    break;
                                    case "DiskUUID":
                                        try {
                                            if (descN.getNodeName().equals("string"))
                                                diskUUID = UUID.fromString(descN.getTextContent());
                                        }
                                        catch(Exception e)
                                        {
                                            e.printStackTrace();
                                        }
                                        break;
									case "Writable":
										writable = descN.getNodeName().equals("true");

										break;
									case "BusProtocol":
										if (descN.getNodeName().equals("string"))
											protocol = descN.getTextContent();

										break;
								}
								currentKey=null;
							}
						}

						if (volumeUUID==null)
                        {
                            if (deviceNode!=null && diskSize!=-1)
                                disks.add(new Disk(diskUUID,diskSize,internal,deviceBlockSize,protocol, deviceNode, mediaName));
                        }
                        else if (deviceIdentifier != null && mountPoint != null && volumeUUID != null && deviceNode!=null) {
						    int li=-1;
						    for (int m=deviceNode.length()-1;m>=4;m--) {
                                if (deviceNode.charAt(m) == 's') {
                                    li = m;
                                    break;
                                }
                            }
                            if (li<0)
                                continue;
						    if (li<=deviceNode.lastIndexOf("disk"))
						        continue;

						    String diskDevice=deviceNode.substring(0, li);
						    for (Disk disk : disks) {
                                if (disk.getDeviceNode().equals(diskDevice)) {
                                    partitions.add(new Partition(volumeUUID, new File(mountPoint), deviceIdentifier, fileSystemType, fileSystemName, volumeBlockSize, writable, volumeName, size, disk));
                                    break;
                                }
                            }
						}
						break;
					}
				}

				p2.destroy();
			}


		}
		catch(ParserConfigurationException | SAXException e)
		{
			throw new IOException(e);
		}


	}

}

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

import java.util.Objects;
import java.util.UUID;

/**
 * @author Jason Mahdjoub
 * @version 1.0
 * @since MaDKitLanEdition 3.16
 */
public class Disk {
    private final UUID diskUUID;
    private final long diskSize;
    private final boolean internal;
    private final int blockSize;
    private final String protocol;
    private final String deviceNode;
    private final String mediaName;


    Disk(UUID diskUUID, long diskSize, boolean internal, int blockSize, String protocol, String deviceNode, String mediaName) {
        this.diskUUID = diskUUID;
        this.diskSize = diskSize;
        this.internal = internal;
        this.blockSize = blockSize;
        this.protocol = protocol;
        this.deviceNode = deviceNode;
        this.mediaName = mediaName;
    }

    public UUID getDiskUUID() {
        return diskUUID;
    }

    public long getDiskSize() {
        return diskSize;
    }

    public boolean isInternal() {
        return internal;
    }

    public int getBlockSize() {
        return blockSize;
    }

    public String getProtocol() {
        return protocol;
    }

    public String getDeviceNode() {
        return deviceNode;
    }

    public String getMediaName() {
        return mediaName;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Disk disk = (Disk) o;
        if (diskUUID!=null)
            return Objects.equals(diskUUID, disk.diskUUID);

        return Objects.equals(deviceNode, disk.deviceNode);
    }

    @Override
    public int hashCode() {

        if (diskUUID!=null)
            return diskUUID.hashCode();
        return deviceNode.hashCode();
    }

    @Override
    public String toString() {
        return "Disk{" +
                "diskUUID=" + diskUUID +
                ", diskSize=" + diskSize +
                ", internal=" + internal +
                ", blockSize=" + blockSize +
                ", protocol='" + protocol + '\'' +
                ", deviceNode='" + deviceNode + '\'' +
                ", mediaName='" + mediaName + '\'' +
                '}';
    }


}

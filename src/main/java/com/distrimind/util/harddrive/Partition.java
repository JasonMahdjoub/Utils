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
package com.distrimind.util.harddrive;

import java.io.File;
import java.util.Objects;
import java.util.UUID;

/**
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 3.16
 */
public class Partition {
    private final UUID UUID;
    private final File mountPointOrLetter;
    private final String deviceIdentifier;
    private final String partitionType;
    private final String partitionTypeUserVisible;
    private final int blockSizeInBytes;
    private final boolean isWritable;

    private final String volumeName;

    private final long partitionSize;

    private final Disk disk;

    Partition(java.util.UUID UUID, File mountPointOrLetter, String deviceIdentifier, String partitionType, String partitionTypeUserVisible, int blockSizeInBytes, boolean isWritable, String volumeName, long partitionSize, Disk disk) {
        this.UUID = UUID;
        this.mountPointOrLetter = mountPointOrLetter;
        this.deviceIdentifier = deviceIdentifier;
        this.partitionType = partitionType;
        this.partitionTypeUserVisible = partitionTypeUserVisible;
        this.blockSizeInBytes = blockSizeInBytes;
        this.isWritable = isWritable;
        this.volumeName = volumeName;
        this.partitionSize = partitionSize;
        this.disk = disk;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Partition disk = (Partition) o;
        if (UUID!=null)
            return Objects.equals(UUID, disk.UUID);

        return Objects.equals(mountPointOrLetter, disk.mountPointOrLetter);
    }

    @Override
    public int hashCode() {

        if (UUID!=null)
            return UUID.hashCode();
        return mountPointOrLetter.hashCode();
    }

    public java.util.UUID getUUID() {
        return UUID;
    }

    public File getMountPointOrLetter() {
        return mountPointOrLetter;
    }

    public String getDeviceIdentifier() {
        return deviceIdentifier;
    }

    public String getPartitionType() {
        return partitionType;
    }

    public String getPartitionTypeUserVisible() {
        return partitionTypeUserVisible;
    }

    public int getBlockSizeInBytes() {
        return blockSizeInBytes;
    }

    public boolean isWritable() {
        return isWritable && getMountPointOrLetter().canWrite();
    }

    public String getVolumeName() {
        return volumeName;
    }

    public long getPartitionSize() {
        return partitionSize;
    }

    public Disk getDisk() {
        return disk;
    }

    public long getFreeSpace()
    {
        return getMountPointOrLetter().getFreeSpace();
    }
    @Override
    public String toString() {
        return "Partition{" +
                "UUID=" + UUID +
                ", mountPointOrLetter=" + mountPointOrLetter +
                ", deviceIdentifier='" + deviceIdentifier + '\'' +
                ", partitionType='" + partitionType + '\'' +
                ", partitionTypeUserVisible='" + partitionTypeUserVisible + '\'' +
                ", blockSizeInBytes=" + blockSizeInBytes +
                ", isWritable=" + isWritable +
                ", volumeName='" + volumeName + '\'' +
                ", partitionSize=" + partitionSize +
                ", disk=" + disk +
                '}';
    }
}

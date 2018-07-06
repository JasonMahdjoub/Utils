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
    private UUID UUID;
    private File mountPointOrLetter;
    private String deviceIdentifier;
    private String partitionType;
    private String partitionTypeUserVisible;
    private int blockSizeInBytes;
    private boolean isWritable;

    private String volumeName;

    private long partitionSize;

    private Disk disk;

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
        return isWritable;
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

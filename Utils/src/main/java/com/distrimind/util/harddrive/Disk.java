package com.distrimind.util.harddrive;

import java.util.Objects;
import java.util.UUID;

/**
 * @author Jason Mahdjoub
 * @version 1.0
 * @since MaDKitLanEdition 3.16
 */
public class Disk {
    private UUID diskUUID;
    private long diskSize;
    private boolean internal;
    private int blockSize;
    private String protocol;
    private String deviceNode;
    private String mediaName;


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

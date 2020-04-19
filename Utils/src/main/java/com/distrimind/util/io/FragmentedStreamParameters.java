package com.distrimind.util.io;

import java.io.IOException;

/**
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 4.16.0
 */
public class FragmentedStreamParameters implements SecureExternalizable {
	private byte streamPartNumbers;
	private byte offset;
	private transient int bytesToSkip;

	public FragmentedStreamParameters(byte streamPartNumbers, byte offset) {
		if (streamPartNumbers<1)
			throw new IllegalArgumentException();
		if (offset<0)
			throw new IllegalArgumentException();
		if (offset>=streamPartNumbers)
			throw new IllegalArgumentException();
		this.streamPartNumbers = streamPartNumbers;
		this.offset=offset;
		initTransientData();
	}

	private void initTransientData()
	{
		bytesToSkip=streamPartNumbers-1;
	}
	public byte getStreamPartNumbers() {
		return streamPartNumbers;
	}

	public int getByteToSkipAfterRead()
	{
		return bytesToSkip;
	}

	public byte getOffset() {
		return offset;
	}

	@Override
	public int getInternalSerializedSize() {
		return 2;
	}

	@Override
	public void writeExternal(SecuredObjectOutputStream out) throws IOException {
		out.writeByte(streamPartNumbers);
		out.writeByte(offset);
	}

	@Override
	public void readExternal(SecuredObjectInputStream in) throws IOException, ClassNotFoundException {
		streamPartNumbers=in.readByte();
		if (streamPartNumbers<1)
			throw new MessageExternalizationException(Integrity.FAIL);
		offset=in.readByte();
		if (offset<0)
			throw new MessageExternalizationException(Integrity.FAIL);
		if (offset>=streamPartNumbers)
			throw new MessageExternalizationException(Integrity.FAIL);
		initTransientData();
	}
	long getLength(RandomInputStream in) throws IOException {
		return getLength(in.length());

	}
	long getLength(long originalStreamLength)
	{
		long m=originalStreamLength%getStreamPartNumbers();
		return originalStreamLength/getStreamPartNumbers()+(m>0 && m>getOffset()?1:0);
	}
	long getLength(RandomOutputStream out) throws IOException {
		return getLength(out.length());
	}
	long translatePosition(long originalPos, long originalLength) throws IOException {

		if (originalPos > originalLength || originalPos < 0)
			throw new IOException("The given position (" + originalPos + ") is invalid. Attempted a position between 0 and "
					+ originalLength + " excluded.");
		return originalPos*streamPartNumbers+offset;
	}

	void seek(RandomInputStream in, long originalPos) throws IOException {
		in.seek(translatePosition(originalPos, getLength(in)));
	}
	void seek(RandomOutputStream out, long originalPos) throws IOException {
		out.seek(translatePosition(originalPos, getLength(out)));
	}

	long getCurrentPosition(long streamPos)
	{
		return (streamPos-offset)/streamPartNumbers;
	}
	long getCurrentPosition(RandomInputStream in) throws IOException {
		return getCurrentPosition(in.currentPosition());
	}
	long getCurrentPosition(RandomOutputStream out) throws IOException {
		return getCurrentPosition(out.currentPosition());
	}
}

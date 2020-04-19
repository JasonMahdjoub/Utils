package com.distrimind.util.io;

import java.io.IOException;

/**
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 4.16.0
 */
public class FragmentedOutputStream extends RandomOutputStream{
	private final RandomOutputStream out;
	private final FragmentedStreamParameters params;
	private boolean updatePosBeforeWrite=false;

	public FragmentedOutputStream(RandomOutputStream out, FragmentedStreamParameters fragmentedStreamParameters) throws IOException {
		if (out==null)
			throw new NullPointerException();
		if (fragmentedStreamParameters==null)
			throw new NullPointerException();
		this.out = out;
		this.params = fragmentedStreamParameters;
		out.seek(fragmentedStreamParameters.getOffset());
	}

	@Override
	public long length() throws IOException {
		return params.getLength(out);
	}

	@Override
	public void setLength(long newLength) throws IOException {
		out.setLength(newLength*params.getStreamPartNumbers());
	}

	@Override
	public void seek(long _pos) throws IOException {
		updatePosBeforeWrite=false;
		params.seek(out, _pos);
	}

	@Override
	public long currentPosition() throws IOException {
		return params.getCurrentPosition(out);
	}

	@Override
	public boolean isClosed() {
		return out.isClosed();
	}

	@Override
	protected RandomInputStream getRandomInputStreamImpl() throws IOException {
		return new FragmentedInputStream(out.getRandomInputStream(), params, false);
	}

	@Override
	public void write(byte[] b, int off, int len) throws IOException {
		long length=length();
		if ((length | off | len) < 0 || len > length - off)
			throw new IndexOutOfBoundsException();
		if (len==0)
			return;
		long p;
		if (updatePosBeforeWrite)
		{
			long s=(p=out.currentPosition()+params.getByteToSkipAfterRead())+1+params.getStreamPartNumbers()*(len-1);
			out.ensureLength(s);
			out.seek(p);
		}
		else
		{
			long s=out.currentPosition()+params.getStreamPartNumbers()*(len-1);
			out.ensureLength(s);
			p=out.currentPosition();
		}

		for (int i = 0 ; i < len ; i++) {
			out.write(b[off + i]);
			p+=params.getStreamPartNumbers();
			out.seek(p);
		}
		updatePosBeforeWrite=true;
	}

	@Override
	public void write(int b) throws IOException {
		if (updatePosBeforeWrite)
		{
			long s=out.currentPosition()+params.getStreamPartNumbers();
			out.ensureLength(s);
			out.seek(s-1);
		}
		out.write(b);
		updatePosBeforeWrite=true;
	}
}

package com.distrimind.util.io;

import java.io.DataInputStream;
import java.io.EOFException;
import java.io.IOException;

/**
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 4.16.0
 */
public class FragmentedInputStream extends RandomInputStream {
	private final RandomInputStream in;
	private final FragmentedStreamParameters params;



	FragmentedInputStream(RandomInputStream in, FragmentedStreamParameters fragmentedStreamParameters, boolean seek) throws IOException {
		if (in==null)
			throw new NullPointerException();
		if (fragmentedStreamParameters==null)
			throw new NullPointerException();
		this.in = in;
		this.params=fragmentedStreamParameters;
		if (seek)
			in.seek(fragmentedStreamParameters.getOffset());
	}
	public FragmentedInputStream(RandomInputStream in, FragmentedStreamParameters fragmentedStreamParameters) throws IOException {
		this(in, fragmentedStreamParameters, true);
	}

	@Override
	public long length() throws IOException {
		return params.getLength(in);
	}

	@Override
	public void seek(long _pos) throws IOException {
		params.seek(in, _pos);
	}

	@Override
	public long currentPosition() throws IOException {
		return params.getCurrentPosition(in);
	}

	@Override
	public boolean isClosed() {
		return in.isClosed();
	}

	@Override
	public void readFully(byte[] tab, int off, int len) throws IOException {

		while (len>0) {
			int s = in.read(tab, off, len);
			if (s < 0)
				throw new EOFException();
			len -= s;
			off+=s;
		}
	}


	@Override
	public int skipBytes(int n) throws IOException {
		return in.skipBytes(n*params.getStreamPartNumbers());
	}

	@Override
	public void skipNBytes(long _nb) throws IOException {
		in.skipNBytes(_nb*params.getStreamPartNumbers());
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public long skip(long _nb) throws IOException {
		return in.skip(_nb*params.getStreamPartNumbers());
	}


	@Override
	@Deprecated
	public String readLine() throws IOException {
		return new DataInputStream(this).readLine();
	}

	@Override
	public int read() throws IOException {
		int v= in.read();
		in.skipNBytes(params.getByteToSkipAfterRead());
		return v;
	}

	@Override
	public void mark(int readlimit) {
		in.mark(readlimit);
	}

	@Override
	public boolean markSupported() {
		return in.markSupported();
	}

	@Override
	public void reset() throws IOException {
		in.reset();
	}


	@Override
	public void close() throws IOException {
		in.close();
	}

}

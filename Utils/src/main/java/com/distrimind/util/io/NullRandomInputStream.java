package com.distrimind.util.io;

import java.io.EOFException;
import java.io.IOException;

/**
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 5.15.0
 */
public class NullRandomInputStream extends RandomInputStream{
	private long pos;
	private final long length;
	private boolean closed;

	public NullRandomInputStream(long length) {
		if (length<0)
			throw new IllegalArgumentException();
		this.length = length;
		this.pos=0;
		this.closed=false;
	}

	public NullRandomInputStream(long length, long pos) {
		this(length);
		try {
			seek(pos);
		}catch (IOException ignored)
		{

		}
	}

	@Override
	public long length() throws IOException {
		return length;
	}

	@Override
	public void seek(long _pos) throws IOException {
		if (closed)
			throw new IOException();
		if (_pos<0)
			throw new IllegalArgumentException();
		if (_pos>length)
			throw new IllegalArgumentException();
		this.pos=_pos;
	}

	@Override
	public boolean isClosed() {
		return closed;
	}

	@Override
	public void readFully(byte[] tab, int off, int len) throws IOException {
		if (closed)
			throw new IOException();
		checkLimits(tab, off, len);
		if (len+pos>length)
			throw new EOFException();
		pos+=len;
	}

	@Override
	public String readLine() throws IOException {
		if (closed)
			throw new IOException();
		return "";
	}

	@Override
	public int read() throws IOException {
		if (closed)
			throw new IOException();
		if (pos+1>length)
			return -1;
		pos+=1;
		return 0;
	}

	@Override
	public void close() throws IOException {
		closed=true;
	}

	@Override
	public long currentPosition() throws IOException {
		return pos;
	}
}

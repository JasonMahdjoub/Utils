package com.distrimind.util.io;

import java.io.EOFException;
import java.io.IOException;

/**
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 4.16.0
 */
public class LimitedRandomOutputStream extends RandomOutputStream{
	private RandomOutputStream out;
	private long off;
	private long maxLength;
	private long length;
	private long pos;
	public LimitedRandomOutputStream(RandomOutputStream out, long off) throws IOException {
		this.maxLength = -1;
		init(out, off);
	}
	public LimitedRandomOutputStream(RandomOutputStream out, long off, long maxLength) throws IOException {
		set(out, off, maxLength);
	}
	public void set(RandomOutputStream out, long off) throws IOException {
		this.maxLength = -1;
		init(out, off);
	}
	public void set(RandomOutputStream out, long off, long maxLength) throws IOException {
		if (maxLength<0)
			throw new IllegalArgumentException();
		this.maxLength = maxLength;
		init(out, off);
	}

	private void init(RandomOutputStream out, long off) throws IOException {
		if (out==null)
			throw new NullPointerException();
		if (off<0)
			throw new IllegalArgumentException();
		if (off>out.length())
			throw new IllegalArgumentException();
		this.out = out;
		this.off = off;
		this.pos=off;
		out.seek(off);
		this.length=computeLength();
	}

	private long computeLength() throws IOException {
		long l=out.length()-off;
		if (maxLength>=0 && l>maxLength)
			l=maxLength;
		return l;
	}

	@Override
	public long length() {
		return length;
	}

	@Override
	public void write(int b) throws IOException {
		if (maxLength>=0 && pos+1>maxLength)
			throw new EOFException();
		out.write(b);
		++pos;
		length=Math.max(length, pos);
	}

	@Override
	public void write(byte[] b, int off, int len) throws IOException {
		if (len<0)
			throw new IllegalArgumentException();
		if (maxLength>=0 && pos+len>maxLength)
			throw new EOFException();
		out.write(b, off, len);
		pos+=len;
		length=Math.max(length, pos);
	}

	@Override
	public void setLength(long newLength) throws IOException {
		if (maxLength>=0 && newLength>maxLength)
			throw new EOFException();
		out.setLength(off+newLength);
		this.length=newLength;
		this.pos=Math.min(this.length, this.pos);
	}

	@Override
	public void seek(long _pos) throws IOException {
		if (_pos<0 || _pos>length)
			throw new IllegalArgumentException();
		out.seek(_pos+off);
		this.pos=_pos;
	}

	@Override
	public long currentPosition() {
		return pos;
	}

	@Override
	public boolean isClosed() {
		return out.isClosed();
	}

	@Override
	protected RandomInputStream getRandomInputStreamImpl() throws IOException {
		if (maxLength<0)
			return new LimitedRandomInputStream(out.getRandomInputStream(), off);
		else
			return new LimitedRandomInputStream(out.getRandomInputStream(), off, length);
	}

	@Override
	public void flush() throws IOException {
		out.flush();
	}

	@Override
	public void close() throws IOException {
		out.close();
	}
}

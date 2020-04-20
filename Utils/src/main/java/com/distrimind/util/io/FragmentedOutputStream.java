package com.distrimind.util.io;

import com.distrimind.util.Reference;

import java.io.IOException;

/**
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 4.16.0
 */
public class FragmentedOutputStream extends RandomOutputStream{
	private final RandomOutputStream out;
	private final FragmentedStreamParameters params;
	private int offsetToApply=0;

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
		offsetToApply=0;
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

		if ((off | len) < 0 || len > b.length - off)
			throw new IndexOutOfBoundsException();
		if (len==0)
			return;
		long p;
		if (this.offsetToApply>0)
		{
			long s=(p=out.currentPosition()+offsetToApply)+1+params.getStreamPartNumbers()*(len-1);
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
		offsetToApply=params.getByteToSkipAfterRead();
	}
	public int writeChannels(byte[][] tabs) throws IOException {
		if (tabs==null)
			throw new NullPointerException();
		int [] offs=new int[tabs.length];
		int[] lens=new int[tabs.length];

		for (int i=0;i<tabs.length;i++)
		{
			lens[i]=tabs[i].length;
			offs[i]=0;
		}
		return writeChannels(tabs, offs, lens);
	}

	public int writeChannels(byte[][] tabs, int []offs, int []lens) throws IOException {
		if (params.getOffset()!=0)
			throw new IllegalArgumentException("Offset of fragmented stream must be set to 0 when using function");

		Reference<Integer> offsetToApply=new Reference<>();
		final int maxSize=params.checkChannelsParams(tabs, offs, lens, offsetToApply);

		if (maxSize==0)
			return 0;
		long p;
		if (this.offsetToApply>0)
		{
			long s=(p=out.currentPosition()+this.offsetToApply)+maxSize;
			out.ensureLength(s);
			out.seek(p);
		}
		else
		{
			long s=out.currentPosition()+maxSize;
			out.ensureLength(s);
			p=out.currentPosition();
		}
		++p;
		byte[] buffer=new byte[Math.min(BufferedRandomInputStream.MAX_BUFFER_SIZE, maxSize)];
		int indexChannel=0;
		int i=0;
		do {
			int bs = Math.min(buffer.length, maxSize - i);
			for (int indexBuf=0; indexBuf<bs; i++, p++, indexChannel = (indexChannel + 1) % params.getStreamPartNumbers(), indexBuf++) {
				int len = lens[indexChannel]--;
				int off = offs[indexChannel]++;
				if (len > 0) {
					buffer[indexBuf]=tabs[indexChannel][off];
				}
			}
			out.write(buffer, 0, bs);
		} while(i<maxSize);

		this.offsetToApply=offsetToApply.get();
		return maxSize;
	}

	public void writeChannels(int []b) throws IOException {
		if (params.getOffset()!=0)
			throw new IllegalArgumentException("Offset of fragmented stream must be set to 0 when using function");
		if (b==null)
			throw new NullPointerException();
		if (b.length!=params.getStreamPartNumbers())
			throw new IllegalArgumentException();
		if (offsetToApply>0)
		{
			long s=out.currentPosition()+offsetToApply+1;
			out.ensureLength(s+params.getStreamPartNumbers());
			out.seek(s-1);
		}
		else
		{
			out.ensureLength(out.currentPosition()+params.getStreamPartNumbers());
		}
		for (int v : b) {
			if (v<0)
				out.seek(out.currentPosition()+1);
			else
				out.write(v);
		}
		offsetToApply=0;
	}

	@Override
	public void write(int b) throws IOException {
		if (offsetToApply>0)
		{
			long s=out.currentPosition()+offsetToApply+1;
			out.ensureLength(s);
			out.seek(s-1);
		}
		out.write(b);
		offsetToApply=params.getByteToSkipAfterRead();
	}

}

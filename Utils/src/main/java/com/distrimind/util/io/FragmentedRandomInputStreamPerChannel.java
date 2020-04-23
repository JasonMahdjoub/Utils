/*
Copyright or © or Copr. Jason Mahdjoub (01/04/2013)

jason.mahdjoub@distri-mind.fr

This software (Object Oriented Database (OOD)) is a computer program
whose purpose is to manage a local database with the object paradigm
and the java langage

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
package com.distrimind.util.io;

import java.io.EOFException;
import java.io.IOException;

/**
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 4.16.0
 */
public class FragmentedRandomInputStreamPerChannel extends RandomInputStream {
	private final RandomInputStream in;
	private final FragmentedStreamParameters params;



	FragmentedRandomInputStreamPerChannel(FragmentedStreamParameters fragmentedStreamParameters, RandomInputStream in, boolean seek) throws IOException {
		if (in==null)
			throw new NullPointerException();
		if (fragmentedStreamParameters==null)
			throw new NullPointerException();
		this.in = in;
		this.params=fragmentedStreamParameters;
		if (seek)
			in.seek(fragmentedStreamParameters.getOffset());
	}
	public FragmentedRandomInputStreamPerChannel(FragmentedStreamParameters fragmentedStreamParameters, RandomInputStream in) throws IOException {
		this(fragmentedStreamParameters, in, true);
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
		checkLimits(tab, off, len);
		while (len>0) {
			int s = read(tab, off, len);
			if (s < 0)
				throw new EOFException();
			len -= s;
			off+=s;
		}
	}



	@Override
	public void skipNBytes(long _nb) throws IOException {
		if (_nb<=0)
			return;
		in.skipNBytes(_nb*params.getStreamPartNumbers());
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public long skip(long _nb) throws IOException {
		if (_nb<=0)
			return 0;
		return in.skip(_nb*params.getStreamPartNumbers());
	}


	@Override
	@Deprecated
	public String readLine() throws IOException {
		throw new IOException(new IllegalAccessException());
	}

	@Override
	public int read() throws IOException {
		int v= in.read();
		if (v>=0)
			in.skipBytes(params.getByteToSkipAfterRead());
		return v;
	}

	/*public int readChannels(int[] channels) throws IOException {
		if (params.getOffset()!=0)
			throw new IllegalArgumentException("Offset of fragmented stream must be set to 0 when using function");
		if (channels==null)
			throw new NullPointerException();
		if (channels.length!=params.getStreamPartNumbers())
			throw new IllegalArgumentException();
		for (int i=0;i<channels.length;i++) {
			int v=channels[i] = in.read();
			if (v<0)
				return i;
		}
		return channels.length;
	}
	public int readChannels(byte[][] tabs) throws IOException {
		if (tabs==null)
			throw new NullPointerException();
		int [] offs=new int[tabs.length];
		int[] lens=new int[tabs.length];

		for (int i=0;i<tabs.length;i++)
		{
			lens[i]=tabs[i].length;
			offs[i]=0;
		}
		return readChannels(tabs, offs, lens);
	}
	public int readChannels(byte[][] tabs, int[] offs, int[] lens) throws IOException {
		return readChannels(tabs, offs, lens, false);
	}

	private int readChannels(byte[][] tabs, int[] offs, int[] lens, boolean fully) throws IOException {
		if (params.getOffset()!=0)
			throw new IllegalArgumentException("Offset of fragmented stream must be set to 0 when using function");
		Reference<Integer> offsetToApply=new Reference<>();
		final int maxSize=params.checkChannelsParams(tabs, offs, lens, offsetToApply);
		int indexChannel=0;
		byte[] buffer=new byte[Math.min(BufferedRandomInputStream.MAX_BUFFER_SIZE, maxSize)];
		int i=0;
		do {
			int bs = Math.min(buffer.length, maxSize - i);
			bs = in.read(buffer, 0, bs);
			if (bs < 0) {
				if (fully)
					throw new EOFException();
				else
					return i;
			}

			for (int bufIndex=0;bufIndex<bs; i++, indexChannel = (indexChannel + 1) % params.getStreamPartNumbers(), bufIndex++) {
				int len = lens[indexChannel]--;
				int off = offs[indexChannel]++;
				if (len>0)
					tabs[indexChannel][off] = buffer[bufIndex];
			}
		} while(i<maxSize);
		for (i=offsetToApply.get();i>0;i--) {
			if (in.read()<0)
				break;
		}
		return maxSize;
	}
	public int readChannelsFully(byte[][] tabs) throws IOException {
		if (tabs==null)
			throw new NullPointerException();
		int [] offs=new int[tabs.length];
		int[] lens=new int[tabs.length];

		for (int i=0;i<tabs.length;i++)
		{
			lens[i]=tabs[i].length;
			offs[i]=0;
		}
		return readChannelsFully(tabs, offs, lens);
	}
	public int readChannelsFully(byte[][] tabs, int[] offs, int[] lens) throws IOException {

		return readChannels(tabs, offs, lens, true);
	}*/

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

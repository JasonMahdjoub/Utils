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

import java.io.IOException;

/**
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 4.16.0
 */
public class FragmentedRandomOutputStreamPerChannel extends RandomOutputStream{
	private final RandomOutputStream out;
	private final FragmentedStreamParameters params;
	private int offsetToApply=0;

	public FragmentedRandomOutputStreamPerChannel(FragmentedStreamParameters fragmentedStreamParameters, RandomOutputStream out) throws IOException {
		if (out==null)
			throw new NullPointerException();
		if (fragmentedStreamParameters==null)
			throw new NullPointerException();
		this.out = out;
		this.params = fragmentedStreamParameters;
		out.ensureLength(fragmentedStreamParameters.getOffset());
		out.seek(fragmentedStreamParameters.getOffset());
	}

	@Override
	public long length() throws IOException {
		return params.getLength(out);
	}

	@Override
	public void setLength(long newLength) throws IOException {
		long curPos=currentPosition();
		out.setLength(newLength*params.getStreamPartNumbers()+params.getOffset());
		if (curPos>newLength)
			seek(newLength);
	}

	@Override
	public void seek(long _pos) throws IOException {
		if (isClosed())
			throw new IOException("Stream closed");
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
		return new FragmentedRandomInputStreamPerChannel(params, out.getRandomInputStream(),false);
	}

	@Override
	public void write(byte[] b, int off, int len) throws IOException {
		RandomInputStream.checkLimits(b, off, len);
		if (isClosed())
			throw new IOException("Stream closed");
		if (len==0)
			return;
		long p;
		if (this.offsetToApply>0)
		{
			long s=(p=out.currentPosition()+offsetToApply)+1+params.getStreamPartNumbers()*(len-1);
			out.ensureLength(s);
		}
		else
		{
			long s=out.currentPosition()+params.getStreamPartNumbers()*(len-1);
			out.ensureLength(s);
			p=out.currentPosition();
		}
		int s=off+len;
		for (int i = off ; i < s ; i++) {
			out.seek(p);
			out.write(b[off + i]);
			p+=params.getStreamPartNumbers();
		}
		offsetToApply=params.getByteToSkipAfterRead();
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

	@Override
	public void flush() throws IOException {
		out.flush();
	}

	@Override
	public void close() throws IOException {
		out.close();
	}
}

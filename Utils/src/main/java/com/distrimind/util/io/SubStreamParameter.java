package com.distrimind.util.io;
/*
Copyright or © or Copr. Jason Mahdjoub (01/04/2013)

jason.mahdjoub@distri-mind.fr

This software (Object Oriented Database (OOD)) is a computer program 
whose purpose is to manage a local database with the object paradigm 
and the java language

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

import java.io.IOException;

/**
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 4.16.0
 */
public class SubStreamParameter implements SecureExternalizable, Comparable<SubStreamParameter>{
	public static final int MAX_INTERVAL_LENGTH_IN_BYTES=512;
	private long streamStartIncluded;
	private long streamEndExcluded;


	SubStreamParameter() {
	}

	public SubStreamParameter(long streamStartIncluded, long streamEndExcluded) {
		if (streamStartIncluded<0)
			throw new IllegalArgumentException();
		if (streamEndExcluded<=streamStartIncluded)
			throw new IllegalArgumentException();
		if (streamEndExcluded-streamStartIncluded>MAX_INTERVAL_LENGTH_IN_BYTES)
			throw new IllegalArgumentException();
		this.streamStartIncluded = streamStartIncluded;
		this.streamEndExcluded = streamEndExcluded;
	}

	public long getStreamStartIncluded() {
		return streamStartIncluded;
	}

	public long getStreamEndExcluded() {
		return streamEndExcluded;
	}

	@Override
	public int getInternalSerializedSize() {
		return 16;
	}

	@Override
	public void writeExternal(SecuredObjectOutputStream out) throws IOException {
		out.writeLong(streamStartIncluded);
		out.writeLong(streamEndExcluded);
	}

	@Override
	public void readExternal(SecuredObjectInputStream in) throws IOException {
		streamStartIncluded=in.readLong();
		streamEndExcluded=in.readLong();
		if (streamStartIncluded<0)
			throw new MessageExternalizationException(Integrity.FAIL);
		if (streamEndExcluded<=streamStartIncluded)
			throw new MessageExternalizationException(Integrity.FAIL);
		if (streamEndExcluded-streamStartIncluded>MAX_INTERVAL_LENGTH_IN_BYTES)
			throw new MessageExternalizationException(Integrity.FAIL);
	}

	@Override
	public int compareTo(SubStreamParameter o) {
		int r=Long.compare(streamStartIncluded, o.streamStartIncluded);
		if (r==0)
			return Long.compare(streamEndExcluded, o.streamEndExcluded);
		else
			return r;
	}
}

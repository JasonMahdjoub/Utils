package com.distrimind.util.crypto;
/*
Copyright or © or Corp. Jason Mahdjoub (01/04/2013)

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

import com.distrimind.util.InvalidEncodedValue;
import com.distrimind.util.data_buffers.WrappedString;

/**
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 5.25.0
 */
public class WrappedHashedValueInBase64StringFormat extends WrappedString {
	public static final int MAX_CHARS_NUMBER=WrappedHashedValue.MAX_SIZE_IN_BYTES_OF_HASHED_VALUE*4/3;
	private transient WrappedHashedValue wrappedHashedValue;
	public WrappedHashedValueInBase64StringFormat(WrappedHashedValue wrappedHashedValue) {
		super(wrappedHashedValue);
		this.wrappedHashedValue=new WrappedHashedValue(wrappedHashedValue.getType(), wrappedHashedValue.getHashArray(), wrappedHashedValue.getBytes());
	}

	public WrappedHashedValueInBase64StringFormat(char[] hash) throws InvalidEncodedValue {
		super(hash);
		this.wrappedHashedValue=new WrappedHashedValue(this);
	}

	public WrappedHashedValueInBase64StringFormat(StringBuilder hash) throws InvalidEncodedValue {
		super(hash);
		this.wrappedHashedValue=new WrappedHashedValue(this);
	}
	public WrappedHashedValueInBase64StringFormat(String hash) throws InvalidEncodedValue {
		super(hash);
		this.wrappedHashedValue=new WrappedHashedValue(this);
	}

	@Override
	public WrappedHashedValue toWrappedData() {
		return wrappedHashedValue;
	}

	@Override
	protected void setChars(char[] chars) throws InvalidEncodedValue {
		super.setChars(chars);
		this.wrappedHashedValue=new WrappedHashedValue(this);
	}

	@Override
	public boolean equals(Object o) {
		if (o==null)
			return false;
		if (o instanceof WrappedHashedValueInBase64StringFormat)
			return this.wrappedHashedValue.equals(((WrappedHashedValueInBase64StringFormat) o).wrappedHashedValue);
		else
			return false;
	}

	@Override
	public int hashCode() {
		return this.wrappedHashedValue.hashCode();
	}
	@Override
	public String toString() {
		return this.wrappedHashedValue.toString();
	}
}

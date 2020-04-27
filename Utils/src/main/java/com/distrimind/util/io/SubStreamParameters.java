package com.distrimind.util.io;
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

import com.distrimind.util.crypto.AbstractMessageDigest;
import com.distrimind.util.crypto.AbstractSecureRandom;
import com.distrimind.util.crypto.MessageDigestType;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;

/**
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 4.16.0
 */
public class SubStreamParameters implements SecureExternalizable {
	public static final short MAX_PARAMETERS_NUMBER=256;
	private ArrayList<SubStreamParameter> parameters;
	private MessageDigestType messageDigestType;
	private transient boolean sorted=false;
	@SuppressWarnings("unused")
	private SubStreamParameters() {

	}
	public SubStreamParameters(MessageDigestType messageDigestType, Collection<SubStreamParameter> parameters) {
		if (parameters==null)
			throw new NullPointerException();
		if (parameters.size()==0)
			throw new NullPointerException();
		if (parameters.size()>MAX_PARAMETERS_NUMBER)
			throw new NullPointerException();
		if (messageDigestType==null)
			throw new NullPointerException();

		this.parameters = new ArrayList<>(parameters);
		this.messageDigestType = messageDigestType;
	}
	public SubStreamParameters(final MessageDigestType messageDigestType, long globalStreamLength, long subStreamLength, final AbstractSecureRandom random) {
		if (random==null)
			throw new NullPointerException();
		if (globalStreamLength<=0)
			throw new IllegalArgumentException();
		if (subStreamLength<=0)
			throw new IllegalArgumentException();
		if (subStreamLength<globalStreamLength)
			throw new IllegalArgumentException();
		if (messageDigestType==null)
			throw new NullPointerException();
		this.parameters = new ArrayList<>();
		this.messageDigestType = messageDigestType;
		long pos=0;
		while (globalStreamLength>0 && subStreamLength>0)
		{
			long maxSkip=globalStreamLength-subStreamLength-1;
			long skip;
			if (maxSkip<=0)
				skip=0;
			else
				skip=(long)(random.nextDouble()*maxSkip);
			pos+=skip;
			long l=subStreamLength;
			long l2=Math.min(subStreamLength-32, l);
			if (l2>0)
				l+=(long)(random.nextDouble()*l2);

			parameters.add(new SubStreamParameter(pos, pos+l));
			pos+=l+1;
			subStreamLength-=l;
			globalStreamLength-=l+1;
		}
	}

	@Override
	public int getInternalSerializedSize() {
		return 2+parameters.size()*parameters.get(0).getInternalSerializedSize()+SerializationTools.getInternalSize(messageDigestType );
	}

	@Override
	public void writeExternal(SecuredObjectOutputStream out) throws IOException {
		out.writeShort(parameters.size());
		for (SubStreamParameter p : parameters)
		{
			p.writeExternal(out);
		}
		out.writeObject(messageDigestType, false);
	}

	@Override
	public void readExternal(SecuredObjectInputStream in) throws IOException, ClassNotFoundException {
		short s=in.readShort();
		if (s<=0)
			throw new MessageExternalizationException(Integrity.FAIL);
		if (s>MAX_PARAMETERS_NUMBER)
			throw new MessageExternalizationException(Integrity.FAIL);
		parameters=new ArrayList<>(s);
		for (int i=0;i<s;i++)
		{
			SubStreamParameter p=new SubStreamParameter( );
			p.readExternal(in);
		}
		messageDigestType=in.readObject(false, MessageDigestType.class);
		sorted=false;
	}
	private void checkSort()
	{
		if (!sorted)
		{
			Collections.sort(this.parameters);
			sorted=true;
		}
	}
	public byte[] generateHash(RandomInputStream inputStream) throws IOException, NoSuchProviderException, NoSuchAlgorithmException {
		AbstractMessageDigest messageDigest=messageDigestType.getMessageDigestInstance();
		messageDigest.reset();
		return partialHash(inputStream, messageDigest).digest();
	}
	public AbstractMessageDigest partialHash(RandomInputStream inputStream, AbstractMessageDigest messageDigest) throws IOException{
		if (inputStream==null)
			throw new NullPointerException();
		checkSort();
		byte[] buffer=new byte[1024];
		for (SubStreamParameter p : parameters)
		{
			inputStream.seek(p.getStreamStartIncluded());
			long l = p.getStreamEndExcluded() - p.getStreamStartIncluded();
			do {
				int s = (int) Math.min(buffer.length, l);
				inputStream.readFully(buffer, 0, s);
				messageDigest.update(buffer, 0, s);
				l -= s;
			} while(l>0);
		}
		return messageDigest;
	}

	public ArrayList<SubStreamParameter> getParameters() {
		checkSort();
		return parameters;
	}

	public MessageDigestType getMessageDigestType() {
		return messageDigestType;
	}
}

/*
Copyright or © or Copr. Jason Mahdjoub (04/02/2016)

jason.mahdjoub@distri-mind.fr

This software (Utils) is a computer program whose purpose is to give several kind of tools for developers 
(ciphers, XML readers, decentralized id generators, etc.).

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
package com.distrimind.util.crypto;

import java.nio.ByteBuffer;

import gnu.vm.java.security.DigestException;
import java.security.MessageDigest;

/**
 * 
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 2.0
 */
public final class JavaNativeMessageDigest extends AbstractMessageDigest
{
    private final MessageDigest messageDigest;

    JavaNativeMessageDigest(MessageDigest messageDigest)
    {
	this.messageDigest = messageDigest;
    }

    @Override
    public JavaNativeMessageDigest clone() throws CloneNotSupportedException
    {
	return new JavaNativeMessageDigest(
		(MessageDigest) messageDigest.clone());
    }

    @Override
    public byte[] digest()
    {
	return messageDigest.digest();
    }

    @Override
    public byte[] digest(byte[] _input)
    {
	return messageDigest.digest(_input);
    }

    @Override
    public int digest(byte[] _buf, int _offset, int _len) throws DigestException
    {
	try
	{
	    return messageDigest.digest(_buf, _offset, _len);
	}
	catch (java.security.DigestException e)
	{
	    throw new DigestException(e);
	}
    }

    @Override
    public String getAlgorithm()
    {
	return messageDigest.getAlgorithm();
    }

    @Override
    public int getDigestLength()
    {
	return messageDigest.getDigestLength();
    }

    @Override
    public String getProvider()
    {
	return messageDigest.getProvider().getName();
    }

    @Override
    public void reset()
    {
	messageDigest.reset();

    }

    @Override
    public String toString()
    {
	return messageDigest.toString();
    }

    @Override
    public void update(byte _input)
    {
	messageDigest.update(_input);

    }

    @Override
    public void update(byte[] _input)
    {
	messageDigest.update(_input);

    }

    @Override
    public void update(byte[] _input, int _offset, int _len)
    {
	messageDigest.update(_input, _offset, _len);

    }

    @Override
    public void update(ByteBuffer _input)
    {
	messageDigest.update(_input);

    }

}

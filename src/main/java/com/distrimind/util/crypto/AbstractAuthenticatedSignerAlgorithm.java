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

import com.distrimind.util.io.RandomInputStream;

import java.io.IOException;
import java.security.SignatureException;

/**
 * 
 * @author Jason Mahdjoub
 * @version 3.0
 * @since Utils 2.10.0
 */
public abstract class AbstractAuthenticatedSignerAlgorithm {
	public byte[] sign(byte[] bytes)
			throws IOException {
		return sign(bytes, 0, bytes.length);
	}

	public byte[] sign(byte[] bytes, int off, int len)
			throws IOException
	{
		init();
		update(bytes, off, len);
		return getSignature();
	}

	public void sign(byte[] message, int offm, int lenm, byte[] signature, int off_sig, int len_sig)
			throws IOException
	{
		init();
		update(message, offm, lenm);
		getSignature(signature, off_sig);
		
	}
	
	public abstract void init() throws IOException;

	private final byte[] one=new byte[1];

	public void update(byte c) throws IOException
	{
		one[0]=c;
		update(one);
	}

	public void update(byte[] message) throws IOException
	{
		update(message,0, message.length);
	}
	
	public abstract void update(byte[] message, int offm, int lenm) throws IOException ;

	/**
	 * Generates signature bytes of all the data fed to this instance and stores it
	 * in the designated array. The format of the result depends on the underlying
	 * signature algorithm.
	 *
	 * <p>
	 * After calling this method, the instance is reset to its initial state and can
	 * then be used to generate additional signatures.
	 * </p>
	 *
	 * <p>
	 * <b>IMPLEMENTATION NOTE:</b> Neither this method nor the GNU provider will
	 * return partial digests. If <code>len</code> is less than the signature
	 * length, this method will throw a {@link SignatureException}. If it is greater
	 * than or equal then it is ignored.
	 * </p>
	 *
	 * @param signature
	 *            array of bytes of where to store the resulting signature bytes.
	 * @param off_sig
	 *            the offset to start at in the array.
	 * @return the real number of bytes used.
	 * @throws IOException
	 *             if an IO issue occurs.
	 *
	 */
	public abstract int getSignature(byte[] signature, int off_sig) throws IOException;
	
    /**
     * Returns the length of the MAC in bytes.
     *
     * @return the MAC length in bytes.
     */
	public abstract int getMacLengthBytes();
	
	public abstract byte[] getSignature() throws IOException;

	public abstract boolean isPostQuantumSigner();

	private byte[] buffer=null;

	public void update(RandomInputStream inputStream) throws IOException {
		long l=inputStream.length()-inputStream.currentPosition();
		if (l==0)
			return;
		if (buffer==null)
			buffer=new byte[8192];
		do {
			int s=(int)Math.min(buffer.length, l);
			inputStream.readFully(buffer, 0, s);
			update(buffer, 0, s);
			l-=s;
		} while (l>0);
	}
	protected abstract void checkKeysNotCleaned();

}

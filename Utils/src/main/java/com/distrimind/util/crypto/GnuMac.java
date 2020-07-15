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

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;


/**
 * 
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 2.10.0
 */
public final class GnuMac extends AbstractMac {
	private final Object mac;

	GnuMac(Object mac) {
		if (mac == null)
			throw new NullPointerException();
		this.mac = mac;
	}

	@Override
	public int hashCode() {
		return mac.hashCode();
	}

	@Override
	public boolean equals(Object _obj) {
		if (_obj==null)
			return false;
		if (_obj instanceof GnuMac)
			return mac.equals(((GnuMac) _obj).mac);
		else {
			try {
				if (Class.forName("com.distrimind.gnuvm.jgnux.crypto.Mac").isAssignableFrom(_obj.getClass()))
					return mac.equals(_obj);
				else
					return false;
			} catch (ClassNotFoundException e) {
				e.printStackTrace();
				return false;
			}
		}

	}

	@Override
	public final GnuMac clone() throws CloneNotSupportedException {
		return new GnuMac(GnuFunctions.clone(mac));
	}

	@Override
	public final byte[] doFinal() throws IOException {
		return GnuFunctions.macDoFinal(mac);
	}

	@Override
	public final byte[] doFinal(byte[] _input) throws IOException {
		return GnuFunctions.macDoFinal(mac, _input);
	}

	@Override
	public final void doFinal(byte[] _output, int _outOffset) throws IOException {
		GnuFunctions.macDoFinal(mac, _output, _outOffset);
	}

	@Override
	public String toString() {
		return mac.toString();
	}

	@Override
	public final String getAlgorithm() {
		return GnuFunctions.macGetAlgorithm(mac);
	}

	@Override
	public final int getMacLengthBytes() {
		return GnuFunctions.macGetLengthByes(mac);
	}

	@Override
	public final void init(AbstractKey _key) throws IOException {
		try {
			GnuFunctions.macInit(mac, _key);
		} catch (NoSuchAlgorithmException e) {
			throw new IOException(e);
		}
	}

	@Override
	public final void reset() {
		GnuFunctions.macReset(mac);
	}

	@Override
	public final void update(byte _input) throws IOException {
		GnuFunctions.macUpdate(mac, _input);
	}

	@Override
	public final void update(byte[] _input) throws IOException {
		GnuFunctions.macUpdate(mac, _input, 0, _input.length);
	}

	@Override
	public final void update(byte[] _input, int _offset, int _length) throws IOException {
		GnuFunctions.macUpdate(mac, _input, _offset, _length);
	}

	@Override
	public final void update(ByteBuffer _buffer) {
		GnuFunctions.macUpdate(mac, _buffer);
	}
}

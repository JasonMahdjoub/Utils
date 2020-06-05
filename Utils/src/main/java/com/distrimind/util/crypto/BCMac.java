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
import java.security.spec.InvalidKeySpecException;

import com.distrimind.util.io.Integrity;
import com.distrimind.util.io.MessageExternalizationException;
import org.bouncycastle.bccrypto.Digest;
import org.bouncycastle.bccrypto.digests.Blake2bDigest;
import org.bouncycastle.bccrypto.digests.SHA3Digest;
import org.bouncycastle.crypto.fips.FipsOutputMACCalculator;

import org.bouncycastle.bccrypto.macs.HMac;
import org.bouncycastle.bccrypto.params.KeyParameter;

/**
 * 
 * @author Jason Mahdjoub
 * @version 3.0
 * @since Utils 3.10.0
 */
public final class BCMac extends AbstractMac {

	private final SymmetricAuthentifiedSignatureType type;

	private org.bouncycastle.crypto.SymmetricSecretKey secretKey;
	private HMac mac;

	BCMac(SymmetricAuthentifiedSignatureType type)
	{
		this.type=type;

	}
	
	@Override
	public int hashCode() {
		return mac.hashCode();
	}

	@Override
	public String getAlgorithm() {
		return type.getAlgorithmName();
	}

	@Override
	public boolean equals(Object _obj) {
		if (_obj instanceof BCMac)
			return mac.equals(((BCMac) _obj).mac);
		else if (_obj instanceof FipsOutputMACCalculator)
			return mac.equals(_obj);
		else
			return false;
	}

	@Override
	public String toString() {
		return mac.toString();
	}

	@Override
	public int getMacLengthBytes() {
		
		return mac.getMacSize();
	}

	@Override
	public void init(AbstractKey _key) throws IOException {
		try {
			init((org.bouncycastle.crypto.SymmetricSecretKey)_key.toBouncyCastleKey());
		} catch (NoSuchAlgorithmException e) {
			throw new IOException(e);
		}
		catch (InvalidKeySpecException e)
		{
			throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN, e);
		}
	}
	
	public void init(org.bouncycastle.crypto.SymmetricSecretKey _key) throws IOException {
		Digest d;
		if (type.getCodeProviderForSignature()==CodeProvider.BC)
		{
			switch(type.getMessageDigestType())
			{
				case BC_FIPS_SHA3_256:
					d=new SHA3Digest(256);
					break;
				case BC_FIPS_SHA3_384:
					d=new SHA3Digest(384);
					break;
				case BC_FIPS_SHA3_512:
					d=new SHA3Digest(512);
					break;
				case BC_BLAKE2B_160:case BC_BLAKE2B_256:
				case BC_BLAKE2B_384:case BC_BLAKE2B_512:
					d=new Blake2bDigest(type.getMessageDigestType().getDigestLengthInBits());
				break;
				default:
					throw new IOException(new NoSuchAlgorithmException(type.toString()));
			}
		}
		else {
			throw new IOException(new NoSuchAlgorithmException(type.toString()));
		}
		mac=new HMac(d);
		mac.init(new KeyParameter((secretKey=_key).getKeyBytes()));
		reset();

	}

	@Override
	public void update(byte _input)  {
		mac.update(_input);

	}

	@Override
	public void update(byte[] _input)  {
		this.update(_input, 0, _input.length);

	}

	@Override
	public void update(byte[] _input, int _offset, int _len) {
		mac.update(_input, _offset,_len);

	}

	@Override
	public void update(ByteBuffer _input) {
		mac.update(_input.array(), _input.position(), _input.remaining());
	}

	@Override
	public byte[] doFinal()  {
		byte[] res=new byte[mac.getMacSize()];
		doFinal(res, 0);
		return res;
	}

	@Override
	public void doFinal(byte[] _output, int _outOffset) {
		mac.doFinal(_output, _outOffset);
		reset();

	}

	@Override
	public byte[] doFinal(byte[] _input) {
		update(_input);
		return doFinal();
	}

	@Override
	public void reset() {

	}

	@Override
	public BCMac clone() throws CloneNotSupportedException {

        BCMac res=new BCMac(type);
		try {
			res.init(secretKey);
		} catch (IOException e) {
			throw new CloneNotSupportedException(e.getMessage());
		}
		return res;

	}

}

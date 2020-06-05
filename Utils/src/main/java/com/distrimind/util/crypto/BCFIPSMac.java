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

import com.distrimind.util.io.Integrity;
import com.distrimind.util.io.MessageExternalizationException;
import org.bouncycastle.crypto.UpdateOutputStream;
import org.bouncycastle.crypto.fips.FipsOutputMACCalculator;
import org.bouncycastle.crypto.fips.FipsSHS;
import org.bouncycastle.crypto.fips.FipsSHS.AuthParameters;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

/**
 * 
 * @author Jason Mahdjoub
 * @version 2.0
 * @since Utils 3.22.0
 */
public final class BCFIPSMac extends AbstractMac {

	private final SymmetricAuthentifiedSignatureType type;
	private final int macLength;
	private org.bouncycastle.crypto.SymmetricSecretKey secretKey;
	private FipsOutputMACCalculator<AuthParameters> mac;
	private UpdateOutputStream macStream;

	BCFIPSMac(SymmetricAuthentifiedSignatureType type)
	{
		this.type=type;
		macLength=type.getSignatureSizeInBits()/8;
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
		if (_obj instanceof BCFIPSMac)
			return mac.equals(((BCFIPSMac) _obj).mac);
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
		
		return macLength;
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
		if (type.getCodeProviderForSignature()==CodeProvider.BC)
		{
			throw new IOException(new NoSuchAlgorithmException(type.toString()));
		}
		else {
			FipsSHS.MACOperatorFactory fipsFacto = new FipsSHS.MACOperatorFactory();
			mac = fipsFacto.createOutputMACCalculator(secretKey = _key, type.getMessageDigestAuth());
			reset();
		}
	}

	@Override
	public void update(byte _input) throws IOException {
		macStream.write(_input);
	}

	@Override
	public void update(byte[] _input) throws IOException {
		macStream.write(_input);

	}

	@Override
	public void update(byte[] _input, int _offset, int _len) throws IOException {
		macStream.write(_input, _offset, _len);

	}

	@Override
	public void update(ByteBuffer _input) {
		macStream.update(_input.array(), _input.position(), _input.remaining());
	}

	@Override
	public byte[] doFinal() throws IOException {
		macStream.close();
		byte[] res = mac.getMAC();
		reset();
		return res;
	}

	@Override
	public void doFinal(byte[] _output, int _outOffset) throws IOException {
		macStream.close();
		mac.getMAC(_output, _outOffset);
		reset();
	}

	@Override
	public byte[] doFinal(byte[] _input) throws IOException {
		update(_input);
		return doFinal();
	}

	@Override
	public void reset() {
		macStream=mac.getMACStream();
	}

	@Override
	public BCFIPSMac clone() throws CloneNotSupportedException {

        BCFIPSMac res=new BCFIPSMac(type);
		try {
			res.init(secretKey);
		} catch (IOException e) {
			throw new CloneNotSupportedException(e.getMessage());
		}
        return res;

	}

}

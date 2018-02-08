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
import java.io.Serializable;

import org.apache.commons.codec.binary.Base64;

import com.distrimind.util.Bits;

/**
 * 
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 2.0
 */
public abstract class Key implements Serializable {
	
	
	
	/**
	 * 
	 */
	private static final long serialVersionUID = -8425241891004940479L;



	abstract gnu.vm.jgnu.security.Key toGnuKey()
			throws gnu.vm.jgnu.security.NoSuchAlgorithmException, gnu.vm.jgnu.security.spec.InvalidKeySpecException;

	abstract java.security.Key toJavaNativeKey()
			throws gnu.vm.jgnu.security.NoSuchAlgorithmException, gnu.vm.jgnu.security.spec.InvalidKeySpecException;
	
	abstract org.bouncycastle.crypto.Key toBouncyCastleKey() throws gnu.vm.jgnu.security.NoSuchAlgorithmException, gnu.vm.jgnu.security.spec.InvalidKeySpecException;
	
	abstract byte[] encode();

	
	public static Key decode(byte[] b) throws IllegalArgumentException {
		byte[][] res = Bits.separateEncodingsWithShortSizedTabs(b);
		if (res[0][0]==(byte)2)
			return new SymmetricSecretKey(SymmetricEncryptionType.valueOf(Bits.getInt(res[0], 1)), res[1],
				Bits.getShort(res[0], 5));
		else if (res[0][0]==(byte)3)
			return new SymmetricSecretKey(SymmetricAuthentifiedSignatureType.valueOf(Bits.getInt(res[0], 1)), res[1],
					Bits.getShort(res[0], 5));
		else if (res[0][0]==(byte)4)
		{
			return new ASymmetricPrivateKey(ASymmetricAuthentifiedSignatureType.valueOf(Bits.getInt(res[0], 3)), res[1],
					Bits.getShort(res[0], 1));
		}
		else if (res[0][0]==(byte)5)
		{
			return new ASymmetricPrivateKey(ASymmetricEncryptionType.valueOf(Bits.getInt(res[0], 3)), res[1],
					Bits.getShort(res[0], 1));
		}
		else if (res[0][0]==(byte)8)
		{
			return new ASymmetricPublicKey(ASymmetricEncryptionType.valueOf(Bits.getInt(res[0], 3)), res[1],
					Bits.getShort(res[0], 1), Bits.getLong(b, 7));
		}
		else if (res[0][0]==(byte)9)
		{
			return new ASymmetricPublicKey(ASymmetricAuthentifiedSignatureType.valueOf(Bits.getInt(res[0], 3)), res[1],
					Bits.getShort(res[0], 1), Bits.getLong(b, 7));
		}
		else
			throw new IllegalArgumentException();
			
	}
	
	
	
	public static Key valueOf(String key) throws IllegalArgumentException, IOException {
		return decode(Base64.decodeBase64(key));
	}
}

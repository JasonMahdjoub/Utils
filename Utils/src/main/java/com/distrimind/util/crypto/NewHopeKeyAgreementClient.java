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

import java.util.Arrays;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.pqc.crypto.newhope.NHKeyPairGenerator;
import org.bouncycastle.pqc.crypto.newhope.NHPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.newhope.NHPublicKeyParameters;

/**
 * 
 * @author Jason Mahdjoub
 * @version 1.1
 * @since Utils 3.10.0
 */
public class NewHopeKeyAgreementClient extends AbstractNewHopeKeyAgreement{

	private AbstractSecureRandom randomForKeys;
	private NHPrivateKeyParameters priv;
	protected NewHopeKeyAgreementClient(SymmetricAuthentifiedSignatureType type, AbstractSecureRandom randomForKeys) {
		this(type, 256, randomForKeys);
	}
	protected NewHopeKeyAgreementClient(SymmetricAuthentifiedSignatureType type, int keySizeBits, AbstractSecureRandom randomForKeys) {
		super(type, keySizeBits/8);
		this.randomForKeys=randomForKeys;
	}
	protected NewHopeKeyAgreementClient(SymmetricEncryptionType type, AbstractSecureRandom randomForKeys) {
		this(type, 256, randomForKeys);
	}
	protected NewHopeKeyAgreementClient(SymmetricEncryptionType type, int keySizeBits, AbstractSecureRandom randomForKeys) {
		super(type, keySizeBits/8);
		this.randomForKeys=randomForKeys;
	}
	
	public void zeroize()
	{
		super.zeroize();
		if (priv!=null)
		{
			try {
				short[] f = (short[])fieldSecData.get(priv);
				Arrays.fill(f, (short)0);
			} catch (IllegalArgumentException | IllegalAccessException e) {
				e.printStackTrace();
			}
		}
	}

	public byte[] getDataPhase1()
	{
		//init key pair
		NHKeyPairGenerator keyPairEngine = new NHKeyPairGenerator();
		
		keyPairEngine.init(new KeyGenerationParameters(randomForKeys, 1024));
		AsymmetricCipherKeyPair pair = keyPairEngine.generateKeyPair();
        NHPublicKeyParameters pub = (NHPublicKeyParameters)pair.getPublic();
        priv = (NHPrivateKeyParameters)pair.getPrivate();
        
        return pub.getPubData();
	}
	
	public void setDataPhase2(byte []data)
	{
		//calculate agreement
        shared = new byte[agreementSize];

        sharedA(shared, priv.getSecData(), data);
	}

}

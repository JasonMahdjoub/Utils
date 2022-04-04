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
import java.util.Arrays;

import com.distrimind.util.io.Integrity;
import com.distrimind.util.io.MessageExternalizationException;
import com.distrimind.bouncycastle.crypto.AsymmetricCipherKeyPair;
import com.distrimind.bouncycastle.crypto.CryptoException;
import com.distrimind.bouncycastle.crypto.KeyGenerationParameters;
import com.distrimind.bouncycastle.pqc.crypto.newhope.NHKeyPairGenerator;
import com.distrimind.bouncycastle.pqc.crypto.newhope.NHPrivateKeyParameters;
import com.distrimind.bouncycastle.pqc.crypto.newhope.NHPublicKeyParameters;

/**
 *
 * @author Jason Mahdjoub
 * @version 1.1
 * @since Utils 3.10.0
 */
public class NewHopeKeyAgreementClient extends AbstractNewHopeKeyAgreement{
	private static final class Finalizer extends Cleaner
	{
		private NHPrivateKeyParameters priv;
		@Override
		protected void performCleanup() {
			if (priv!=null)
			{
				try {
					short[] f = (short[])fieldSecData.get(priv);
					Arrays.fill(f, (short)0);
					priv=null;
				} catch (IllegalArgumentException | IllegalAccessException e) {
					e.printStackTrace();
				}
			}
		}
	}
	private final Finalizer finalizer;
	private final AbstractSecureRandom randomForKeys;

	private boolean valid=true;
	NewHopeKeyAgreementClient(SymmetricAuthenticatedSignatureType type, short keySizeBits, AbstractSecureRandom randomForKeys) {
		super(type, (short)(keySizeBits/8));
		this.randomForKeys=randomForKeys;
		finalizer=new Finalizer();
		registerCleaner(finalizer);
	}
	NewHopeKeyAgreementClient(SymmetricEncryptionType type, short keySizeBits, AbstractSecureRandom randomForKeys) {
		super(type, (short)(keySizeBits/8));
		this.randomForKeys=randomForKeys;
		finalizer=new Finalizer();
		registerCleaner(finalizer);
	}

	@Override
	public boolean isPostQuantumAgreement() {
		return true;
	}

	private byte[] getDataPhase1()
	{
		valid=false;
		//init key pair
		NHKeyPairGenerator keyPairEngine = new NHKeyPairGenerator();

		keyPairEngine.init(new KeyGenerationParameters(randomForKeys, 1024));
		AsymmetricCipherKeyPair pair = keyPairEngine.generateKeyPair();
		NHPublicKeyParameters pub = (NHPublicKeyParameters)pair.getPublic();
		finalizer.priv = (NHPrivateKeyParameters)pair.getPrivate();

		byte[] res=pub.getPubData();
		valid=true;
		return res;
	}

	private void setDataPhase2(byte []data)
	{
		//calculate agreement
		valid=false;
		super.finalizer.shared = new byte[agreementSize];

		sharedA(super.finalizer.shared, finalizer.priv.getSecData(), data);
		valid=true;
	}
	@Override
	protected boolean isAgreementProcessValidImpl() {
		return valid;
	}
	@Override
	protected byte[] getDataToSend(int stepNumber) throws IOException {
		if (!valid)
			throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN, new CryptoException());

		try {
			if (stepNumber == 0)
				return getDataPhase1();
			else {
				valid = false;
				throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN, new IllegalAccessException());
			}
		}
		catch(Exception e)
		{
			valid=false;
			throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN, e);
		}
	}
	@Override
	protected void receiveData(int stepNumber, byte[] data) throws IOException {
		if (!valid)
			throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN, new CryptoException());

		try {
			if (stepNumber == 0)
				setDataPhase2(data);
			else
				throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN, new IllegalAccessException());
		}
		catch(Exception e)
		{
			valid=false;
			throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN, new CryptoException("", e));
		}


	}


}

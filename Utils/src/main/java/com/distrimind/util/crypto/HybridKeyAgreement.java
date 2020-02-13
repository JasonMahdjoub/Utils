package com.distrimind.util.crypto;
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

import com.distrimind.util.Bits;
import org.bouncycastle.bccrypto.CryptoException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

/**
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 4.5.0
 */
public class HybridKeyAgreement extends KeyAgreement{
	private final KeyAgreement nonPQCKeyAgreement, PQCKeyAgreement;
	private SymmetricSecretKey secretKey=null;

	protected HybridKeyAgreement(KeyAgreement nonPQCKeyAgreement, KeyAgreement PQCKeyAgreement)
	{
		super(Math.max(nonPQCKeyAgreement.getStepsNumberForReception(),PQCKeyAgreement.getStepsNumberForReception())
				, Math.max(nonPQCKeyAgreement.getStepsNumberForSend(),PQCKeyAgreement.getStepsNumberForSend()));
		if (PQCKeyAgreement.getDerivedKeySizeBytes()<32)
			throw new IllegalArgumentException("Derived key size of PQC algorithm must be greater than 256 bits");
		if (nonPQCKeyAgreement.isPostQuantumAgreement())
			throw new IllegalArgumentException();
		if (!PQCKeyAgreement.isPostQuantumAgreement())
			throw new IllegalArgumentException();
		this.nonPQCKeyAgreement=nonPQCKeyAgreement;
		this.PQCKeyAgreement=PQCKeyAgreement;
	}

	@Override
	public SymmetricSecretKey getDerivedKey() {
		return secretKey;
	}

	@Override
	public short getDerivedKeySizeBytes() {
		return  PQCKeyAgreement.getDerivedKeySizeBytes();
	}


	private void checkSymmetricSecretKey() throws CryptoException
	{
		if (secretKey==null && hasFinishedReception() && hasFinishedSend())
		{
			SymmetricSecretKey nonPQC=nonPQCKeyAgreement.getDerivedKey();
			SymmetricSecretKey PQC=PQCKeyAgreement.getDerivedKey();

			byte[] PQCBytes=PQC.getKeyBytes();

			try {
				SymmetricSecretKey k=nonPQC;
				if (k.getEncryptionAlgorithmType()==null)
					k=new SymmetricSecretKey(SymmetricEncryptionType.AES_CBC_PKCS5Padding, k.getKeyBytes());
				AbstractCipher cipher=k.getEncryptionAlgorithmType().getCipherInstance();
				byte[] iv=new byte[k.getEncryptionAlgorithmType().getIVSizeBytes()];
				Arrays.fill(iv, (byte)0);
				cipher.init(Cipher.ENCRYPT_MODE, k, iv);
				byte[] shared=cipher.doFinal(PQCBytes, 0, PQCBytes.length);
				int s=shared.length-PQCBytes.length;
				if (s>0) {
					for (int i = 0; i < s; i++) {
						shared[i] ^= shared[i + PQCBytes.length];
					}
					shared=Arrays.copyOfRange(shared, 0, PQCBytes.length);
				}

				if (shared.length<32)
					throw new CryptoException();
				if (PQC.getEncryptionAlgorithmType()==null)
					secretKey=new SymmetricSecretKey(PQC.getAuthenticatedSignatureAlgorithmType(), shared);
				else
					secretKey=new SymmetricSecretKey(PQC.getEncryptionAlgorithmType(), shared);

			} catch (NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException | InvalidKeyException | InvalidKeySpecException | IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException e) {
				throw new CryptoException("", e);
			}
		}
	}

	@Override
	protected boolean isAgreementProcessValidImpl() {
		return nonPQCKeyAgreement.isAgreementProcessValidImpl() && PQCKeyAgreement.isAgreementProcessValidImpl();
	}

	@Override
	protected byte[] getDataToSend(int stepNumber) throws Exception {
		try {
			byte[] nonPQC = null, PQC = null;
			boolean nonPQCb=false, PQCb=false;
			if (!nonPQCKeyAgreement.hasFinishedSend()) {
				nonPQC = nonPQCKeyAgreement.getDataToSend();
				nonPQCb = true;
			}
			if (!PQCKeyAgreement.hasFinishedSend()) {
				PQC = PQCKeyAgreement.getDataToSend();
				PQCb = true;
			}
			if (nonPQCb && PQCb) {
				byte[] res = new byte[nonPQC.length + PQC.length + 3];
				Bits.putPositiveInteger(res, 0, nonPQC.length, 3);
				System.arraycopy(nonPQC, 0, res, 3, nonPQC.length);
				System.arraycopy(PQC, 0, res, 3 + nonPQC.length, PQC.length);
				return res;
			} else if (nonPQCb)
				return nonPQC;
			else
				return PQC;
		}
		finally {
			checkSymmetricSecretKey();
		}
	}

	KeyAgreement getNonPQCKeyAgreement() {
		return nonPQCKeyAgreement;
	}

	KeyAgreement getPQCKeyAgreement() {
		return PQCKeyAgreement;
	}

	@Override
	protected void receiveData(int stepNumber, byte[] data) throws CryptoException {
		try {
			byte[] nonPQC = null, PQC = null;
			if (!nonPQCKeyAgreement.hasFinishedReception() && !PQCKeyAgreement.hasFinishedReception()) {
				int s = (int) Bits.getPositiveInteger(data, 0, 3);
				if (s + 36 > data.length)
					throw new CryptoException();
				nonPQC = new byte[s];
				PQC = new byte[data.length - s - 3];
				System.arraycopy(data, 3, nonPQC, 0, nonPQC.length);
				System.arraycopy(data, 3 + s, PQC, 0, PQC.length);
			} else if (!nonPQCKeyAgreement.hasFinishedReception())
				nonPQC = data;
			else
				PQC = data;
			if (!nonPQCKeyAgreement.hasFinishedReception())
				nonPQCKeyAgreement.receiveData(nonPQC);
			if (!PQCKeyAgreement.hasFinishedReception())
				PQCKeyAgreement.receiveData(PQC);
		}
		finally
		{
			checkSymmetricSecretKey();
		}

	}

	@Override
	public void zeroize() {
		nonPQCKeyAgreement.zeroize();
		PQCKeyAgreement.zeroize();
		this.secretKey=null;
	}

	@Override
	public boolean isPostQuantumAgreement() {
		return true;
	}
}

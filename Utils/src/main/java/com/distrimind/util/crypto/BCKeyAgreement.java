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
import com.distrimind.bcfips.crypto.AsymmetricPrivateKey;
import com.distrimind.bcfips.crypto.AsymmetricPublicKey;
import com.distrimind.bcfips.crypto.KDFCalculator;
import com.distrimind.bcfips.crypto.fips.FipsAgreement;
import com.distrimind.bcfips.crypto.fips.FipsEC;
import com.distrimind.bcfips.crypto.fips.FipsEC.AgreementParameters;
import com.distrimind.bouncycastle.jcajce.spec.UserKeyingMaterialSpec;
import com.distrimind.bcfips.util.Arrays;
import com.distrimind.bcfips.crypto.fips.FipsKDF;
import com.distrimind.bcfips.crypto.fips.FipsKDF.AgreementKDFParameters;

import javax.crypto.ShortBufferException;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

/**
 * 
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 3.10.0
 */
public final class BCKeyAgreement extends AbstractKeyAgreement{
	private final EllipticCurveDiffieHellmanType type;
	private FipsAgreement<?> agreement;
	private byte []secret;
	private FipsKDF.AgreementKDFParametersBuilder kdfAlgorithm;
	private byte[] paramsKeyMaterial;
	
	protected BCKeyAgreement(SymmetricAuthenticatedSignatureType signatureType, EllipticCurveDiffieHellmanType type) {
		super(signatureType);
		this.type=type;
		//CodeProvider.ensureProviderLoaded(type.getCodeProvider());
	}
	
	protected BCKeyAgreement(SymmetricEncryptionType encryptionType, EllipticCurveDiffieHellmanType type) {
		super(encryptionType);
		this.type=type;
		//CodeProvider.ensureProviderLoaded(type.getCodeProvider());
	}

	@Override
	public void doPhase(AbstractKey key, boolean lastPhase)
			throws IOException {
		if (agreement==null)
			throw new NullPointerException();
		try {
			secret=agreement.calculate((AsymmetricPublicKey)key.toBouncyCastleKey());
		} catch (NoSuchAlgorithmException e) {
			throw new IOException(e);
		}
		catch (InvalidKeySpecException e)
		{
			throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN, e);
		}
	}

	@Override
	public byte[] generateSecret() {
		byte[] res = secret;
		secret=null;
		return res;
	}

	@Override
	public int generateSecret(byte[] sharedSecret, int offset) throws IOException {
		byte[] secret = generateSecret();

        if (sharedSecret.length - offset < secret.length)
        {
            throw new IOException(new ShortBufferException(getAlgorithm() + " key agreement: need "
                + secret.length + " bytes"));
        }

        System.arraycopy(secret, 0, sharedSecret, offset, secret.length);

        return secret.length;
	}

	@Override
	public SymmetricSecretKey generateSecretKey(short keySize)
			 {
		byte[] secret = generateSecret();
		if (type.useKDF())
        {
            byte[] keyBytes = new byte[keySize];

            FipsKDF.AgreementKDFParameters params = kdfAlgorithm.using(secret).withIV(paramsKeyMaterial);

            FipsKDF.AgreementOperatorFactory kdfOperatorFactory= new FipsKDF.AgreementOperatorFactory();
            
            KDFCalculator<AgreementKDFParameters> kdf = kdfOperatorFactory.createKDFCalculator(params);

            kdf.generateBytes(keyBytes, 0, keyBytes.length);

            Arrays.fill(secret, (byte)0);

            secret = keyBytes;
        }
        else
        {
            byte[] key = new byte[keySize];

            System.arraycopy(secret, 0, key, 0, key.length);

            Arrays.fill(secret, (byte)0);

            secret = key;
        }

        if (encryptionType==null)
        		return new SymmetricSecretKey(signatureType, new com.distrimind.bcfips.crypto.SymmetricSecretKey(signatureType.getBouncyCastleAlgorithm(), secret), (short)(keySize*8));
        else
        		return new SymmetricSecretKey(encryptionType, new com.distrimind.bcfips.crypto.SymmetricSecretKey(encryptionType.getBouncyCastleAlgorithm(), secret), (short)(keySize*8));
	}

	@Override
	public String getAlgorithm() {
		
		return type.getKeyAgreementAlgorithmName();
	}


    
	
	@Override
	public void init(AbstractKey key, Object params, AbstractSecureRandom random) throws IOException {
		try {
			if (type.isECCDHType() || type.isXDHType()) {

				paramsKeyMaterial = ((UserKeyingMaterialSpec) params).getUserKeyingMaterial();
				AgreementParameters aParams = FipsEC.CDH.withDigest(type.getBCFipsDigestAlgorithm())
						.withKDF(kdfAlgorithm = FipsKDF.CONCATENATION.withPRF(type.getBCFipsAgreementKDFPRF()), paramsKeyMaterial, paramsKeyMaterial.length);
				FipsEC.DHAgreementFactory agreementFact = new FipsEC.DHAgreementFactory();

				agreement = agreementFact.createAgreement((AsymmetricPrivateKey) key.toBouncyCastleKey(), aParams);

			} else if (type.isECMQVType()) {
				Object[] p = (Object[]) params;
				com.distrimind.bcfips.crypto.fips.FipsEC.MQVAgreementParameters mqvparam = (com.distrimind.bcfips.crypto.fips.FipsEC.MQVAgreementParameters) p[0];
				paramsKeyMaterial = (byte[]) p[1];

				mqvparam = mqvparam.withDigest(type.getBCFipsDigestAlgorithm())
						.withKDF(kdfAlgorithm = FipsKDF.CONCATENATION.withPRF(type.getBCFipsAgreementKDFPRF()), paramsKeyMaterial, paramsKeyMaterial.length);

				FipsEC.MQVAgreementFactory mqvagreementfact = new FipsEC.MQVAgreementFactory();

				agreement = mqvagreementfact.createAgreement((AsymmetricPrivateKey) key.toBouncyCastleKey(), mqvparam);
			} else
				throw new InternalError();
			secret = null;
		}
		catch (NoSuchAlgorithmException e) {
			throw new IOException(e);
		}
		catch (InvalidKeySpecException e)
		{
			throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN, e);
		}
		
	}


}

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



import org.bouncycastle.crypto.AsymmetricPrivateKey;
import org.bouncycastle.crypto.AsymmetricPublicKey;
import org.bouncycastle.crypto.KDFCalculator;
import org.bouncycastle.crypto.fips.FipsAgreement;
import org.bouncycastle.crypto.fips.FipsEC;
import org.bouncycastle.crypto.fips.FipsEC.AgreementParameters;
import org.bouncycastle.jcajce.spec.UserKeyingMaterialSpec;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.crypto.fips.FipsKDF;
import org.bouncycastle.crypto.fips.FipsKDF.AgreementKDFParameters;

import gnu.vm.jgnu.security.NoSuchAlgorithmException;
import gnu.vm.jgnu.security.spec.InvalidKeySpecException;
import gnu.vm.jgnux.crypto.ShortBufferException;

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
	private byte[] paramskeymaterial;
	
	protected BCKeyAgreement(SymmetricAuthentifiedSignatureType signatureType, EllipticCurveDiffieHellmanType type) {
		super(signatureType);
		this.type=type;
		CodeProvider.ensureBouncyCastleProviderLoaded();
	}
	
	protected BCKeyAgreement(SymmetricEncryptionType encryptionType, EllipticCurveDiffieHellmanType type) {
		super(encryptionType);
		this.type=type;
		CodeProvider.ensureBouncyCastleProviderLoaded();
	}

	@Override
	public void doPhase(Key key, boolean lastPhase)
			throws IllegalStateException, NoSuchAlgorithmException, InvalidKeySpecException {
		secret=agreement.calculate((AsymmetricPublicKey)key.toBouncyCastleKey());
	}

	@Override
	public byte[] generateSecret() throws IllegalStateException {
		byte res[]=secret;
		secret=null;
		return res;
	}

	@Override
	public int generateSecret(byte[] sharedSecret, int offset) throws IllegalStateException, ShortBufferException {
		byte[] secret = generateSecret();

        if (sharedSecret.length - offset < secret.length)
        {
            throw new ShortBufferException(getAlgorithm() + " key agreement: need "
                + secret.length + " bytes");
        }

        System.arraycopy(secret, 0, sharedSecret, offset, secret.length);

        return secret.length;
	}

	@Override
	public SymmetricSecretKey generateSecretKey(short keySize)
			throws IllegalStateException {
		byte secret[]=generateSecret();
		if (type.useKDF())
        {
            byte[] keyBytes = new byte[keySize];

            FipsKDF.AgreementKDFParameters params = kdfAlgorithm.using(secret).withIV(paramskeymaterial);

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
        		return new SymmetricSecretKey(signatureType, new org.bouncycastle.crypto.SymmetricSecretKey(signatureType.getBouncyCastleAlgorithm(), secret), (short)(keySize*8));
        else
        		return new SymmetricSecretKey(encryptionType, new org.bouncycastle.crypto.SymmetricSecretKey(encryptionType.getBouncyCastleAlgorithm(), secret), (short)(keySize*8));
	}

	@Override
	public String getAlgorithm() {
		
		return type.getKeyAgreementAlgorithmName();
	}


    
	
	@Override
	public void init(Key key, Object params) throws NoSuchAlgorithmException, InvalidKeySpecException {
		if (type.isECCDHType())
		{
			paramskeymaterial=((UserKeyingMaterialSpec)params).getUserKeyingMaterial();
			AgreementParameters aparams=FipsEC.CDH.withDigest(type.getBCFipsDigestAlgorithm())
				.withKDF(kdfAlgorithm=FipsKDF.CONCATENATION.withPRF(type.getBCFipsAgreementKDFPRF()), paramskeymaterial, paramskeymaterial.length);
			FipsEC.DHAgreementFactory agreementFact=new FipsEC.DHAgreementFactory();
			agreement=agreementFact.createAgreement((AsymmetricPrivateKey)key.toBouncyCastleKey(), aparams);
			
		}
		else if (type.isECMQVType())
		{
			Object [] p=(Object[])params;
			org.bouncycastle.crypto.fips.FipsEC.MQVAgreementParameters mqvparam=(org.bouncycastle.crypto.fips.FipsEC.MQVAgreementParameters)p[0];
			paramskeymaterial=(byte[])p[1];
			
			mqvparam=mqvparam.withDigest(type.getBCFipsDigestAlgorithm())
					.withKDF(kdfAlgorithm=FipsKDF.CONCATENATION.withPRF(type.getBCFipsAgreementKDFPRF()), paramskeymaterial, paramskeymaterial.length);
			
			FipsEC.MQVAgreementFactory mqvagreementfact=new FipsEC.MQVAgreementFactory();
			
			agreement=mqvagreementfact.createAgreement((AsymmetricPrivateKey)key.toBouncyCastleKey(), mqvparam);
		}
		else
			throw new InternalError();
		secret=null;
		
	}


}

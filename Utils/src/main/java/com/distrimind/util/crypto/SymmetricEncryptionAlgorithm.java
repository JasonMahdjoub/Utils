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

import java.util.Random;

import javax.crypto.Cipher;

import gnu.vm.jgnu.security.InvalidAlgorithmParameterException;
import gnu.vm.jgnu.security.InvalidKeyException;
import gnu.vm.jgnu.security.NoSuchAlgorithmException;
import gnu.vm.jgnu.security.NoSuchProviderException;
import gnu.vm.jgnu.security.spec.InvalidKeySpecException;
import gnu.vm.jgnux.crypto.NoSuchPaddingException;

/**
 * 
 * @author Jason Mahdjoub
 * @version 3.1
 * @since Utils 1.4
 */
public class SymmetricEncryptionAlgorithm extends AbstractEncryptionIOAlgorithm {



	private final SymmetricSecretKey key;

	private final SymmetricEncryptionType type;

	private final AbstractSecureRandom random;
	private final byte iv[];
	
	private final byte blockModeCounterBytes;
	private final boolean internalCounter;
	
	private byte[] externalCounter=null;
	
	public SymmetricEncryptionAlgorithm(AbstractSecureRandom random, SymmetricSecretKey key)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, NoSuchProviderException, InvalidKeySpecException {
		this(random, key, (byte)0, true);
	}
	public SymmetricEncryptionAlgorithm(AbstractSecureRandom random, SymmetricSecretKey key, byte blockModeCounterBytes)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, NoSuchProviderException, InvalidKeySpecException {
		this(random, key, blockModeCounterBytes, false);
	}
	public SymmetricEncryptionAlgorithm(AbstractSecureRandom random, SymmetricSecretKey key, byte blockModeCounterBytes, boolean internalCounter)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, NoSuchProviderException, InvalidKeySpecException {
		super(key.getEncryptionAlgorithmType().getCipherInstance(), key.getEncryptionAlgorithmType().getIVSizeBytes());

		this.type = key.getEncryptionAlgorithmType();
		if (internalCounter && type.getMaxCounterSizeInBytesUsedWithBlockMode()<blockModeCounterBytes)
			throw new IllegalArgumentException(type+" cannot manage a internal counter size greater than "+type.getMaxCounterSizeInBytesUsedWithBlockMode());
		if (!internalCounter && blockModeCounterBytes>8)
			throw new IllegalArgumentException("The external counter size can't be greater than 8");
		if (blockModeCounterBytes<0)
			throw new IllegalArgumentException("The external counter size can't be lower than 0");
		this.blockModeCounterBytes = blockModeCounterBytes;
		this.internalCounter = internalCounter || blockModeCounterBytes==0;
		this.key = key;
		this.random = random;
		iv = new byte[getIVSizeBytesWithExternalCounter()];
		externalCounter=this.internalCounter?null:new byte[blockModeCounterBytes];
		this.cipher.init(Cipher.ENCRYPT_MODE, this.key, generateIV());
		
		initBufferAllocatorArgs();
		
	}
	@Override
	public byte getBlockModeCounterBytes() {
		return blockModeCounterBytes;
	}
	@Override
	public boolean useExternalCounter()
	{
		return !internalCounter;
	}

	@Override
	public int getIVSizeBytesWithExternalCounter()
	{
		return type.getIVSizeBytes()-(internalCounter?blockModeCounterBytes:0);
	}	
	
	private byte[] generateIV() {
		random.nextBytes(iv);
		if (!internalCounter)
		{
			int j=0;
			for (int i=iv.length-externalCounter.length;i<iv.length;i++)
			{
				iv[i]=externalCounter[j++];
			}
		}
		return iv;
	}
	
	

	public int getBlockSize() {
		return cipher.getBlockSize();
	}

	@Override
	protected AbstractCipher getCipherInstance() throws NoSuchAlgorithmException, NoSuchPaddingException, NoSuchProviderException {
		return type.getCipherInstance();
	}

	@Override
	public int getMaxBlockSizeForDecoding() {
		return key.getMaxBlockSize();
	}

	@Override
	public int getMaxBlockSizeForEncoding() {
		return key.getMaxBlockSize();
	}
	
	

	
	
	public SymmetricSecretKey getSecretKey() {
		return key;
	}

	public SymmetricEncryptionType getType() {
		return type;
	}

	@Override
	protected boolean includeIV() {
		return true;
	}

	@Override
	public void initCipherForDecrypt(AbstractCipher cipher, byte[] iv, byte[] externalCounter)
			throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException,
			InvalidKeySpecException, NoSuchProviderException {
		if (!internalCounter && (externalCounter==null || externalCounter.length!=blockModeCounterBytes) && externalCounter.length+iv.length<getIVSizeBytesWithExternalCounter())
			throw new IllegalArgumentException("Please use external counters at every initialization with the defined size "+blockModeCounterBytes);
		if (iv!=null && iv.length<getIVSizeBytesWithoutExternalCounter() && (externalCounter==null || externalCounter.length+iv.length<getIVSizeBytesWithExternalCounter()))
			throw new IllegalArgumentException("Illegal iv size");
		this.externalCounter=externalCounter;
		
		if (iv != null)
		{
			if (!internalCounter && externalCounter!=null && externalCounter.length!=0 && iv!=this.iv)
			{
				for (int i=0;i<iv.length;i++)
				{
					this.iv[i]=iv[i];
				}
				int j=0;
				for (int i=iv.length;i<this.iv.length;i++)
				{
					this.iv[i]=externalCounter[j];
				}
				iv=this.iv;
			}
			cipher.init(Cipher.DECRYPT_MODE, key, iv);
		}
		else
			cipher.init(Cipher.DECRYPT_MODE, key);
	}

	@Override
	public void initCipherForEncrypt(AbstractCipher cipher, byte[] externalCounter) throws InvalidKeyException,
			InvalidAlgorithmParameterException, NoSuchAlgorithmException, InvalidKeySpecException {
		if (!internalCounter && (externalCounter==null || externalCounter.length!=blockModeCounterBytes))
			throw new IllegalArgumentException("Please use external counters at every initialization with the defined size "+blockModeCounterBytes);
		this.externalCounter=externalCounter;
		cipher.init(Cipher.ENCRYPT_MODE, key, generateIV());
	}
	private final Random nonSecureRandom=new Random(System.currentTimeMillis());
	@Override
	public void initCipherForEncryptAndNotChangeIV(AbstractCipher cipher) throws InvalidKeyException,
			NoSuchAlgorithmException, InvalidKeySpecException, InvalidAlgorithmParameterException {
		nonSecureRandom.nextBytes(nullIV);
		cipher.init(Cipher.ENCRYPT_MODE, key, nullIV);
	}
}

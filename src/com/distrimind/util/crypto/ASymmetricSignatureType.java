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

import java.security.NoSuchAlgorithmException;
import java.security.Signature;

/**
 * List of signature algorithms
 * 
 * @author Jason Mahdjoub
 * @version 3
 * @since Utils 1.4
 */
public enum ASymmetricSignatureType
{
    @Deprecated
    SHA1withRSA("SHA1withRSA", CodeProvider.SUN_ORACLE), 
    SHA256withRSA("SHA256withRSA", CodeProvider.SUN_ORACLE), 
    SHA384withRSA("SHA384withRSA", CodeProvider.SUN_ORACLE), 
    SHA512withRSA("SHA512withRSA", CodeProvider.SUN_ORACLE), 
    GNU_SHA256withRSA("SHA256withRSA", CodeProvider.GNU_CRYPTO), 
    GNU_SHA384withRSA("SHA384withRSA", CodeProvider.GNU_CRYPTO), 
    GNU_SHA512withRSA("SHA512withRSA", CodeProvider.GNU_CRYPTO),
    BOUNCY_CASTLE_SHA256withRSA("SHA256withRSA", CodeProvider.BOUNCY_CASTLE), 
    BOUNCY_CASTLE_SHA384withRSA("SHA384withRSA", CodeProvider.BOUNCY_CASTLE), 
    BOUNCY_CASTLE_SHA512withRSA("SHA512withRSA", CodeProvider.BOUNCY_CASTLE);

    private final String algorithmName;

    private final CodeProvider codeProvider;

    private ASymmetricSignatureType(String algorithmName, CodeProvider codeProvider)
    {
	this.algorithmName = algorithmName;
	this.codeProvider = codeProvider;
    }

    public String getAlgorithmName()
    {
	return algorithmName;
    }

    public AbstractSignature getSignatureInstance() throws gnu.vm.jgnu.security.NoSuchAlgorithmException
    {
	if (codeProvider==CodeProvider.GNU_CRYPTO)
	{
	    return new GnuSignature(
		    gnu.vm.jgnu.security.Signature.getInstance(algorithmName));
	}
	else if (codeProvider==CodeProvider.BOUNCY_CASTLE)
	{
	    
	    try
	    {
		return new JavaNativeSignature(Signature.getInstance(algorithmName, CodeProvider.getBouncyProvider()));	    
	    }
	    catch (NoSuchAlgorithmException e)
	    {
		throw new gnu.vm.jgnu.security.NoSuchAlgorithmException(e);
	    }
	    
	}
	else
	{
	    try
	    {
		return new JavaNativeSignature(
			Signature.getInstance(algorithmName));
	    }
	    catch (NoSuchAlgorithmException e)
	    {
		throw new gnu.vm.jgnu.security.NoSuchAlgorithmException(e);
	    }
	}
    }

    public int getSignatureSizeBits(int keySize)
    {
	return keySize;
    }

    public int getSignatureSizeBytes(int keySize)
    {
	return keySize / 8;
    }

    public CodeProvider getCodeProvider()
    {
	return codeProvider;
    }
}

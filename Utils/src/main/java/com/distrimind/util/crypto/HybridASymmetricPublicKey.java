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


/**
 * @author Jason Mahdjoub
 * @version 1.0
 * @since MaDKitLanEdition 4.5.0
 */
public class HybridASymmetricPublicKey extends Key implements HybridKey{

	private final ASymmetricPublicKey nonPQCPublicKey, PQCPublicKey;

	public HybridASymmetricPublicKey(ASymmetricPublicKey nonPQCPublicKey, ASymmetricPublicKey PQCPublicKey) {
		if (nonPQCPublicKey==null)
			throw new NullPointerException();
		if (PQCPublicKey==null)
			throw new NullPointerException();
		if ((nonPQCPublicKey.getEncryptionAlgorithmType()==null)!=(PQCPublicKey.getEncryptionAlgorithmType()==null)
				|| (nonPQCPublicKey.getAuthentifiedSignatureAlgorithmType()==null)!=(PQCPublicKey.getAuthentifiedSignatureAlgorithmType()==null))
			throw new IllegalArgumentException("The given keys must be used both for encryption or both for signature");
		if ((nonPQCPublicKey.getAuthentifiedSignatureAlgorithmType()!=null
				&& nonPQCPublicKey.getAuthentifiedSignatureAlgorithmType().isPostQuantumAlgorithm())
				|| nonPQCPublicKey.getEncryptionAlgorithmType().isPostQuantumAlgorithm())
			throw new IllegalArgumentException("nonPQCPrivateKey cannot be a post quantum algorithm");
		if ((PQCPublicKey.getAuthentifiedSignatureAlgorithmType()!=null
				&& !PQCPublicKey.getAuthentifiedSignatureAlgorithmType().isPostQuantumAlgorithm())
				|| !PQCPublicKey.getEncryptionAlgorithmType().isPostQuantumAlgorithm())
			throw new IllegalArgumentException("PQCPrivateKey must be a post quantum algorithm");
		this.nonPQCPublicKey = nonPQCPublicKey;
		this.PQCPublicKey = PQCPublicKey;
	}

	public ASymmetricPublicKey getNonPQCPublicKey() {
		return nonPQCPublicKey;
	}

	public ASymmetricPublicKey getPQCPublicKey() {
		return PQCPublicKey;
	}

	@Override
	Object toGnuKey(){
		throw new IllegalAccessError();
	}

	@Override
	java.security.Key toJavaNativeKey() {
		throw new IllegalAccessError();
	}

	@Override
	org.bouncycastle.crypto.Key toBouncyCastleKey() {
		throw new IllegalAccessError();
	}

	@Override
	public byte[] encode(boolean includeTimeExpiration) {
		return Key.encodeHybridKey(nonPQCPublicKey, PQCPublicKey, includeTimeExpiration);
	}

	@Override
	public void zeroize() {
		nonPQCPublicKey.zeroize();
		PQCPublicKey.zeroize();
	}

	@Override
	byte[] getKeyBytes() {
		return null;
	}

	@Override
	public boolean isPostQuantumKey() {
		return true;
	}

	@Override
	public byte[] encodeWithDefaultParameters() {
		return encode(true);
	}
}

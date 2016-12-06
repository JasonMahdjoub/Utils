package com.distrimind.util.crypto;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public enum SecureRandomType
{
    DEFAULT(null),
    SPEEDIEST("SHA1PRNG"),
    SHA1PRNG("SHA1PRNG");
    
    private final String algorithmeName;
    
    private SecureRandomType(String algorithmName)
    {
	this.algorithmeName=algorithmName;
    }
    
    public SecureRandom getInstance() throws NoSuchAlgorithmException
    {
	if (algorithmeName==null)
	    return new SecureRandom();
	else
	    return SecureRandom.getInstance(algorithmeName);
    }
    
    public SecureRandom getInstance(byte[] seed) throws NoSuchAlgorithmException
    {
	SecureRandom sr=getInstance();
	sr.setSeed(seed);
	return sr;
    }

    public SecureRandom getInstance(long seed) throws NoSuchAlgorithmException
    {
	SecureRandom sr=getInstance();
	sr.setSeed(seed);
	return sr;
    }
}

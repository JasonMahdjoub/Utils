package com.distrimind.util.crypto;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;

public enum SecureRandomType
{
    DEFAULT(null, null),
    SPEEDIEST("SHA1PRNG", "SUN"),
    SHA1PRNG("SHA1PRNG", "SUN");
    
    private final String algorithmeName;
    private final String provider;
    
    private SecureRandomType(String algorithmName, String provider)
    {
	this.algorithmeName=algorithmName;
	this.provider=provider;
    }
    
    public SecureRandom getInstance() throws NoSuchAlgorithmException, NoSuchProviderException
    {
	if (algorithmeName==null)
	    return new SecureRandom();
	else
	    return SecureRandom.getInstance(algorithmeName, provider);
    }
    
    public SecureRandom getInstance(byte[] seed) throws NoSuchAlgorithmException, NoSuchProviderException
    {
	SecureRandom sr=getInstance();
	sr.setSeed(seed);
	return sr;
    }

    public SecureRandom getInstance(long seed) throws NoSuchAlgorithmException, NoSuchProviderException
    {
	SecureRandom sr=getInstance();
	sr.setSeed(seed);
	return sr;
    }
}

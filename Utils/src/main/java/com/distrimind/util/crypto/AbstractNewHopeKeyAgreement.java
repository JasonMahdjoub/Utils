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

import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.AccessController;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.security.SecureRandom;
import java.util.Arrays;

import org.bouncycastle.pqc.crypto.newhope.NHPrivateKeyParameters;

/**
 * 
 * @author Jason Mahdjoub
 * @version 1.1
 * @since Utils 3.10.0
 */
public abstract class AbstractNewHopeKeyAgreement extends KeyAgreement{
	private final SymmetricEncryptionType encryptionType;
	private final SymmetricAuthentifiedSignatureType signatureType;
	protected short agreementSize;
	protected byte[] shared;
	private SymmetricSecretKey secretKey=null;

	
	protected AbstractNewHopeKeyAgreement(SymmetricEncryptionType type, short agreementSize)
	{
		super(1, 1);
		this.encryptionType=type;
		this.signatureType=null;
		this.agreementSize=agreementSize;

		if (!type.isPostQuantumAlgorithm((short)(agreementSize*8)))
			throw new IllegalArgumentException("You must use post quantum compatible algorithms");
	}

	@Override
	public short getDerivedKeySizeBytes() {
		return agreementSize;
	}
	
	protected AbstractNewHopeKeyAgreement(SymmetricAuthentifiedSignatureType type, short agreementSize)
	{
		super(1, 1);
		this.encryptionType=null;
		this.signatureType=type;
		this.agreementSize=agreementSize;
		if (!type.isPostQuantumAlgorithm((short)(agreementSize*8)))
			throw new IllegalArgumentException("You must use post quantum compatible algorithms");
	}
	
	public SymmetricSecretKey getDerivedKey()
	{
		if (secretKey==null)
		{
			if (encryptionType==null)
				secretKey=new SymmetricSecretKey(signatureType, shared);
			else
				secretKey=new SymmetricSecretKey(encryptionType, shared);
			shared=null;
		}
		return secretKey;
	}

	@Override
	public void zeroize()
	{
		if (shared!=null)
			Arrays.fill(shared, (byte)0);
		shared=null;
		secretKey=null;
	}
	

	
    //static final int POLY_SIZE;
    static final int SENDB_BYTES;
    static final Method methodShareB;
    static final Method methodShareA;
    static final Field fieldSecData;
    static 
    {
    	
    		//int polySize=1024;
    		int sendBBytes=1792+256;
    		Class<?> newHopeClass=null;
    		try
    		{
    			newHopeClass=Class.forName("org.bouncycastle.pqc.crypto.newhope.NewHope");
    		
	    		/*try
	    		{
	    			Field f=newHopeClass.getDeclaredField("POLY_SIZE");
	    			f.setAccessible(true);
	    			polySize=f.getInt(null);
	    		}
	    		catch(Exception e)
	    		{
	    			e.printStackTrace();
	    		}*/
	    		try
	    		{
	    			Field f=newHopeClass.getDeclaredField("SENDB_BYTES");
	    			f.setAccessible(true);
	    			sendBBytes=f.getInt(null);
	    		}
	    		catch(Exception e)
	    		{
	    			e.printStackTrace();
	    		}
    		}
    		catch(Exception e)
    		{
    			e.printStackTrace();
    			System.exit(-1);
    		}
    		//POLY_SIZE=polySize;
    		SENDB_BYTES=sendBBytes;
    		Class<?> bClass=byte[].class;
    		methodShareA=getMethod(newHopeClass, "sharedA", bClass,short[].class,bClass);
    		methodShareB=getMethod(newHopeClass, "sharedB", SecureRandom.class, bClass,bClass,bClass );
    		fieldSecData=getField(NHPrivateKeyParameters.class, "secData");
    		
    }
	
    static void sharedB(SecureRandom rand, byte[] sharedKey, byte[] send, byte[] received)
    {
    		try {
				invoke(methodShareB, null, rand, sharedKey, send, received);
			} catch (InvocationTargetException e) {
				e.printStackTrace();
			}
    }
    public static void sharedA(byte[] sharedKey, short[] sk, byte[] received)
    {
		try {
			invoke(methodShareA, null, sharedKey, sk, received);
		} catch (InvocationTargetException e) {
			e.printStackTrace();
		}
  	
    }
    @SuppressWarnings({"UnusedReturnValue", "SameParameterValue"})
	static Object invoke(Method m, Object o, Object... args) throws InvocationTargetException {
		try {
			return m.invoke(o, args);
		} catch (IllegalAccessException | IllegalArgumentException e) {
			System.err.println("Impossible to access to the function " + m.getName() + " of the class "
					+ m.getDeclaringClass()
					+ ". This is an inner bug of MadKitLanEdition. Please contact the developers. Impossible to continue. See the next error :");
			e.printStackTrace();
			System.exit(-1);
			return null;
		}
	}
    
    private static Method getMethod(final Class<?> c, final String method_name, final Class<?>... parameters) {
		try {
			
			return AccessController.doPrivileged(new PrivilegedExceptionAction<Method>() {

                @Override
                public Method run() throws Exception {
                    Method m = c.getDeclaredMethod(method_name, parameters);
                    m.setAccessible(true);
                    return m;
                }
            });

				
		} catch (SecurityException | PrivilegedActionException  e) {
			System.err.println("Impossible to access to the function " + method_name + " of the class "
					+ c.getCanonicalName()
					+ ". This is an inner bug of MadKitLanEdition. Please contact the developers. Impossible to continue. See the next error :");
			e.printStackTrace();
			System.exit(-1);
			return null;
		}
	}

    
    
    @SuppressWarnings("SameParameterValue")
	private static Field getField(final Class<?> c, final String method_name) {
		try {
			
			return AccessController.doPrivileged(new PrivilegedExceptionAction<Field>() {

                @Override
                public Field run() throws Exception {
                    Field m = c.getDeclaredField(method_name);
                    m.setAccessible(true);
                    return m;
                }
            });

				
		} catch (SecurityException | PrivilegedActionException  e) {
			e.printStackTrace();
			System.exit(-1);
			return null;
		}
	}
}

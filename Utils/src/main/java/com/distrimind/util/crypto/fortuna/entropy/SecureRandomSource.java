package com.distrimind.util.crypto.fortuna.entropy;


import com.distrimind.util.crypto.AbstractSecureRandom;
import com.distrimind.util.crypto.SecureRandomType;
import com.distrimind.util.crypto.fortuna.accumulator.EntropySource;
import com.distrimind.util.crypto.fortuna.accumulator.EventAdder;
import com.distrimind.util.crypto.fortuna.accumulator.EventScheduler;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.concurrent.TimeUnit;

/**
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 4.0.0
 */
public class SecureRandomSource implements EntropySource {

	private volatile AbstractSecureRandom [] secureRandoms=null;
	private volatile boolean update=true;

	public void add(AbstractSecureRandom random) {
		if (random==null)
			throw new NullPointerException();
		if (secureRandoms==null)
			secureRandoms=new AbstractSecureRandom[]{random};
		else
		{
			AbstractSecureRandom[] t=new AbstractSecureRandom[secureRandoms.length+1];
			System.arraycopy(secureRandoms, 0, t, 0, secureRandoms.length );
			t[secureRandoms.length]=random;
			secureRandoms=t;
		}

	}

	public boolean isUpdate() {
		return update;
	}

	public void setUpdate(boolean update) {
		this.update = update;
	}

	public void add(SecureRandomType type) throws NoSuchProviderException, NoSuchAlgorithmException {
		add(type.getSingleton(null));
	}

	@Override
	public void schedule(EventScheduler scheduler) {
		scheduler.schedule(100, TimeUnit.MILLISECONDS);
	}

	@Override
	public void event(EventAdder adder) {
		if (update) {
			byte numBytes = 32;
			byte[] seed = null;
			/*try {
				seed = SecureRandomType.tryToGenerateNativeNonBlockingSeed(numBytes);
			} catch (java.security.NoSuchAlgorithmException | java.security.NoSuchProviderException e) {
				e.printStackTrace();

			}*/

			byte[] s = null;
			if (secureRandoms != null) {
				for (int i = 0; i < secureRandoms.length; i++) {
					if (s == null)
						s = new byte[numBytes];
					secureRandoms[i].nextBytes(s);
					if (seed == null) {
						seed = s;
						s = null;
					} else {
						for (int j = 0; j < numBytes; j++)
							seed[j] = (byte) (seed[i] ^ s[i]);
					}
				}
			}
			if (seed != null)
				adder.add(seed);
			update=false;
		}
	}
}

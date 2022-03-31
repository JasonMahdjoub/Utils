package com.distrimind.util.crypto.fortuna.entropy;


import com.distrimind.util.crypto.SecureRandomType;
import com.distrimind.util.crypto.fortuna.accumulator.EventAdder;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

/**
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 4.0.0
 */
public class SecureRandomSourceTest {
	private SecureRandomSource target;
	private int adds;

	@BeforeMethod
	public void before() {
		target = new SecureRandomSource();
		adds = 0;
	}

	@Test
	public void shouldAddUptime() throws NoSuchProviderException, NoSuchAlgorithmException {
		target.setUpdate(true);
		target.add(SecureRandomType.SHA1PRNG);
		target.event(new EventAdder() {
			@Override
			public void add(byte[] event) {
				Assert.assertEquals(32, event.length);
				adds++;
			}
		});
		Assert.assertEquals(1, adds);
	}
}

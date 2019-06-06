package com.distrimind.util.crypto.fortuna.entropy;


import com.distrimind.util.crypto.fortuna.accumulator.EventAdder;
import org.testng.Assert;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.Test;

/**
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 4.0.0
 */
public class SecureRandomSourceTest {
	private SecureRandomSource target;
	private int adds;

	@BeforeTest
	public void before() {
		target = new SecureRandomSource();
		adds = 0;
	}

	@Test
	public void shouldAddUptime() {
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

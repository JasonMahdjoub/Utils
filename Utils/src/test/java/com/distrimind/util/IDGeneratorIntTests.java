package com.distrimind.util;

import org.testng.Assert;
import org.testng.annotations.Test;

public class IDGeneratorIntTests {
	@Test
	public void testIDGeneratorInt() {
		int startNumber = 45;
		int bufferSize = 20;
		IDGeneratorInt generator = new IDGeneratorInt(bufferSize, startNumber);
		int numberIds = 1000;
		int ids[] = new int[numberIds];
		Assert.assertEquals(0, generator.getNumberOfMemorizedIds());
		for (int i = 0; i < numberIds; i++) {
			ids[i] = generator.getNewID();
			Assert.assertTrue(generator.getRealTabSize() < generator.getNumberOfMemorizedIds() + bufferSize + 1);
		}
		Assert.assertEquals(numberIds, generator.getNumberOfMemorizedIds());
		Assert.assertTrue(generator.getRealTabSize() < generator.getNumberOfMemorizedIds() + bufferSize + 1);
		for (int i = 0; i < numberIds; i++) {
			for (int j = 0; j < numberIds; j++) {
				if (i != j) {
					Assert.assertNotEquals(Integer.valueOf(ids[i]), Integer.valueOf(ids[j]));
				}
			}
			generator.removeID(ids[i]);
			Assert.assertTrue(generator.getRealTabSize() <= generator.getNumberOfMemorizedIds() + (bufferSize * 2 + 1));
		}
		Assert.assertEquals(generator.getNumberOfMemorizedIds(), 0);
		Assert.assertTrue(generator.getRealTabSize() <= generator.getNumberOfMemorizedIds() + (bufferSize * 2 + 1));
		int id = generator.getNewID();
		Assert.assertEquals(generator.getNumberOfMemorizedIds(), 1);
		Assert.assertEquals(id, startNumber);
		generator.removeID(startNumber);
		Assert.assertEquals(generator.getNumberOfMemorizedIds(), 0);
		Assert.assertTrue(generator.getRealTabSize() <= generator.getNumberOfMemorizedIds() + (bufferSize * 2 + 1));

	}
}

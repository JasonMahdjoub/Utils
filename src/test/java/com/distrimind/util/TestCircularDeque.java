package com.distrimind.util;

import java.util.Deque;

/**
 *
 * @version 1.0
 * @since Utils 4.8.0
 */
public class TestCircularDeque extends TestDeque {


	@Override
	public Deque<String> getDequeInstance() {
		return new CircularArrayList<>();
	}
}

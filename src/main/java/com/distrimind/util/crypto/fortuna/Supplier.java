package com.distrimind.util.crypto.fortuna;


public interface Supplier<T> {

	/**
	 * Gets a result.
	 *
	 * @return a result
	 */
	T get();
}

package com.distrimind.util.crypto;

import javax.security.auth.Destroyable;

/**
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 5.10.0
 */
public interface Zeroizable extends Destroyable {
	void zeroize();

	@Override
	default void destroy() {
		zeroize();
	}
	@Override
	boolean isDestroyed();
}
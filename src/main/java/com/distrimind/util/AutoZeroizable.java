package com.distrimind.util;

import java.io.IOException;

/**
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 5.23.0
 */
public interface AutoZeroizable extends Zeroizable, Cleanable {
	@Override
	default void zeroize()
	{
		CleanerTools.performCleanup(this);
	}
	@Override
	default void clean()
	{
		Cleanable.super.clean();
	}

	@Override
	default void destroy() {
		zeroize();
	}

	@Override
	default boolean isDestroyed()
	{
		return isCleaned();
	}
	@Override
	default void close() {
		clean();
	}
}
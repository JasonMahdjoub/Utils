package com.distrimind.util;

import java.util.Collection;
import java.util.List;

import static org.hamcrest.CoreMatchers.*;

/**
 *
 * @version 1.0
 * @since Utils 4.8.0
 */
public class TestCircularArrayList extends TestList{
	@Override
	protected <T> List<T> getListInstance(Collection<T> c) {
		return new CircularArrayList<>(c);
	}
}

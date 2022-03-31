package com.distrimind.util;


import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.util.*;

import static org.testng.Assert.*;
/**
 * @author <a href="mailto:antoinegrondin@gmail.com">Antoine Grondin</a>
 * @author Jason Mahdjoub
 */
public abstract class DequeTest {

	///////////////////////////////////////////////////////////////////////////
	// Fields
	///////////////////////////////////////////////////////////////////////////

	// Statics
	private final static int MAX_PROBLEM_SIZE = 10000;

	// Members
	private Deque<String> mDequeue;


	// Constructors

	public abstract Deque<String> getDequeueInstance();

	@BeforeMethod
	public void setUp() {
		mDequeue = getDequeueInstance();
	}

	@AfterMethod
	public void tearDown() {
		mDequeue = null;
	}

	///////////////////////////////////////////////////////////////////////////
	// Test
	///////////////////////////////////////////////////////////////////////////

	@Test
	public void testDeque() {
		assertNotNull( mDequeue );
	}

	@Test
	public void testIsEmpty() {
		assertTrue(mDequeue.isEmpty(), "Initialized queue should be empty");
	}

	@Test
	public void testIsEmptyAfterAddRemoveFirst() {
		mDequeue.addFirst("Something");
		boolean empty = mDequeue.isEmpty();
		assertFalse( empty );
		mDequeue.removeFirst();

		empty = mDequeue.isEmpty();
		assertTrue(empty, "Should be empty after adding then removing");

	}

	@Test
	public void testIsEmptyAfterAddRemoveLast() {
		mDequeue.addLast("Something");
		assertFalse(mDequeue.isEmpty());
		mDequeue.removeLast();
		assertTrue(mDequeue.isEmpty(), "Should be empty after adding then removing");

	}

	@Test
	public void testIsEmptyAfterAddFirstRemoveLast() {
		mDequeue.addFirst("Something");
		assertFalse(mDequeue.isEmpty());
		mDequeue.removeLast();
		assertTrue(mDequeue.isEmpty(), "Should be empty after adding then removing");
	}

	@Test
	public void testIsEmptyAfterAddLastRemoveFirst() {
		mDequeue.addLast("Something");
		assertFalse(mDequeue.isEmpty());
		mDequeue.removeFirst();
		assertTrue(mDequeue.isEmpty(), "Should be empty after adding then removing");
	}

	@Test
	public void testIsEmptyAfterMultipleAddRemove(){
		for(int i = 0; i < MAX_PROBLEM_SIZE; i++){
			mDequeue.addFirst("Something");
			assertFalse(mDequeue.isEmpty(), "Should not be empty after " + i + " item added");
		}

		for(int i = 0; i < MAX_PROBLEM_SIZE; i++){
			assertFalse(mDequeue.isEmpty(), "Should not be empty after " + i + " item removed");
			mDequeue.removeLast();
		}

		assertTrue( mDequeue.isEmpty(), "Should be empty after adding and removing "
				+ MAX_PROBLEM_SIZE + " elements.");
	}

	@Test
	public void testMultipleFillAndEmpty(){
		for(int tries = 0; tries < 50; tries++){
			for(int i = 0; i < MAX_PROBLEM_SIZE; i++){
				mDequeue.addFirst(String.valueOf(i));
			}

			assertFalse( mDequeue.isEmpty() );
			int i = 0;
			while( !mDequeue.isEmpty() ){
				assertEquals( mDequeue.removeLast(), String.valueOf(i) );
				i++;
			}

			assertTrue( mDequeue.isEmpty() );

			for(int j = 0; j < MAX_PROBLEM_SIZE; j++){
				mDequeue.addLast(String.valueOf(j));
			}

			assertFalse( mDequeue.isEmpty() );

			i = 0;
			while( !mDequeue.isEmpty() ){
				assertEquals( mDequeue.removeFirst(), String.valueOf(i) );
				i++;
			}

			assertTrue( mDequeue.isEmpty() );
		}
	}

	@Test
	public void testSize() {
		assertEquals( 0, mDequeue.size() );
		for(int i = 0; i < MAX_PROBLEM_SIZE; i++){
			mDequeue.addFirst("Something");
			assertEquals(mDequeue.size(),i+1 );
		}

		for(int i = MAX_PROBLEM_SIZE; i > 0; i--){
			assertEquals(mDequeue.size(),i );
			mDequeue.removeLast();
		}

		assertEquals( mDequeue.size(), 0 );
	}

	@Test
	public void testAddFirst() {
		String[] aBunchOfString = {
				"One",
				"Two",
				"Three",
				"Four"
		};

		for(String aString : aBunchOfString){
			mDequeue.addFirst(aString);
		}

		for(int i = aBunchOfString.length - 1; i >= 0; i--){
			assertEquals(mDequeue.removeFirst(), aBunchOfString[i]);
		}
	}

	@Test
	public void testAddLast() {
		String[] aBunchOfString = {
				"One",
				"Two",
				"Three",
				"Four"
		};

		for(String aString : aBunchOfString){
			mDequeue.addLast(aString);
		}

		for(int i = aBunchOfString.length - 1; i >= 0; i--){
			assertEquals(mDequeue.removeLast(), aBunchOfString[i]);
		}
	}

	@Test
	public void testAddNull(){
		try {
			mDequeue.addFirst(null);
			fail("Should have thrown a NullPointerException");
		} catch (NullPointerException npe){
			// Continue
		} catch (Exception e){
			fail("Wrong exception catched." + e);
		}

		try {
			mDequeue.addLast(null);
			fail("Should have thrown a NullPointerException");
		} catch (NullPointerException npe){
			// Continue
		} catch (Exception e){
			fail("Wrong exception catched." + e);
		}
	}

	@Test
	public void testRemoveFirst() {
		for(int i = 0; i < MAX_PROBLEM_SIZE; i++){
			mDequeue.addFirst( String.valueOf(i) );
			assertEquals(mDequeue.removeFirst(), String.valueOf(i));
		}

		mDequeue = getDequeueInstance();

		for(int i = 0; i < MAX_PROBLEM_SIZE; i++){
			mDequeue.addLast( String.valueOf(i) );
			assertEquals(mDequeue.removeFirst(), String.valueOf(i));
		}

		mDequeue = getDequeueInstance();

		for(int i = 0; i < MAX_PROBLEM_SIZE; i++){
			mDequeue.addLast( String.valueOf(i) );
		}

		for(int i = 0; i < MAX_PROBLEM_SIZE; i++){
			assertEquals(mDequeue.removeFirst(), String.valueOf(i));
		}

	}

	@Test
	public void testRemoveLast() {
		for(int i = 0; i < MAX_PROBLEM_SIZE; i++){
			mDequeue.addFirst( String.valueOf(i) );
			assertEquals(mDequeue.removeLast(), String.valueOf(i));
		}

		mDequeue = getDequeueInstance();

		for(int i = 0; i < MAX_PROBLEM_SIZE; i++){
			mDequeue.addLast( String.valueOf(i) );
			assertEquals(mDequeue.removeLast(), String.valueOf(i));
		}

		mDequeue = getDequeueInstance();

		for(int i = 0; i < MAX_PROBLEM_SIZE; i++){
			mDequeue.addFirst( String.valueOf(i) );
		}

		for(int i = 0; i < MAX_PROBLEM_SIZE; i++){
			assertEquals(mDequeue.removeLast(), String.valueOf(i));
		}
	}

	@Test
	public void testRemoveEmpty() {
		try {
			assertTrue(mDequeue.isEmpty());
			mDequeue.removeFirst();
			fail("Expected a NoSuchElementException");
		} catch ( NoSuchElementException nsee){
			// Continue
		} catch ( Exception e ){
			fail( "Unexpected exception : " + e );
		}

		try {
			assertTrue(mDequeue.isEmpty());
			mDequeue.removeLast();
			fail("Expected a NoSuchElementException");
		} catch ( NoSuchElementException nsee){
			// Continue
		} catch ( Exception e ){
			fail( "Unexpected exception : " + e );
		}

		try {
			assertTrue(mDequeue.isEmpty());

			for(int i = 0; i < MAX_PROBLEM_SIZE; i ++ ){
				mDequeue.addLast( String.valueOf(i) );
			}
			for(int i = 0; i < MAX_PROBLEM_SIZE; i ++ ){
				mDequeue.removeLast();
			}
			mDequeue.removeLast();
			fail("Expected a NoSuchElementException");
		} catch ( NoSuchElementException nsee){
			// Continue
		} catch ( Exception e ){
			fail( "Unexpected exception : " + e );
		}
	}

	@Test
	public void testIterator() {

		Iterator<String> anIterator = mDequeue.iterator();
		assertFalse( anIterator.hasNext() );

		for(int i = 0; i < MAX_PROBLEM_SIZE; i++){
			mDequeue.addFirst( String.valueOf(i) );
		}

		anIterator = mDequeue.iterator();

		assertTrue( anIterator.hasNext() );

		int i = MAX_PROBLEM_SIZE - 1;
		for(String aString : mDequeue){
			assertEquals( aString, String.valueOf(i));
			i--;
		}

		anIterator = mDequeue.iterator();

		assertTrue( anIterator.hasNext() );

		int j = MAX_PROBLEM_SIZE - 1;
		while( anIterator.hasNext() ){
			assertEquals( anIterator.next(), String.valueOf(j));
			j--;
		}
	}

	@Test
	public void testIteratorNoMoreItem() {
		Iterator<String> anIterator = mDequeue.iterator();
		while( anIterator.hasNext() ){
			anIterator.next();
		}
		try {
			anIterator.next();
			fail( "Should have thrown a NoSuchElementException.");
		} catch( NoSuchElementException nsee ){
			// Continue
		} catch( Exception e ){
			fail( "Should have thrown a NoSuchElementException, but received" +
					" : " + e);
		}
	}

	@Test
	public void testIteratorRemoveNotSupported() {
		Iterator<String> anIterator = mDequeue.iterator();
		try {
			anIterator.remove();
			fail("Should have thrown an UnsupportedOperationException");
		} catch ( UnsupportedOperationException uoe ){
			// Continue
		} catch ( Exception e ){
			fail( "Unexpected exception : " + e);
		}
	}
	@Test
	public void testRemoveIfNoData() {
		List<String> l=Arrays.asList("1", "2", "3", "4");
		mDequeue.addAll(l);
		assertEquals(mDequeue, l);
		mDequeue.removeIf((v) -> false);
		assertEquals(mDequeue, l);
	}
	@Test
	public void testRemoveIfAll() {
		List<String> l=Arrays.asList("1", "2", "3", "4");
		mDequeue.addAll(l);
		assertEquals(mDequeue, l);
		mDequeue.removeIf((v) -> true);
		assertNotEquals(mDequeue, l);
		assertEquals(mDequeue.size(), 0);
	}
	@Test
	public void testRemoveIfPair() {
		List<String> l=Arrays.asList("1", "2", "3", "4");
		List<String> l2=Arrays.asList("2", "4");
		mDequeue.addAll(l);
		assertEquals(mDequeue, l);
		mDequeue.removeIf((v) -> Integer.parseInt(v)%2==1);
		assertNotEquals(mDequeue, l);
		assertEquals(mDequeue, l2);
	}
	@Test
	public void testRemoveIfImpair() {
		List<String> l=Arrays.asList("1", "2", "3", "4");
		List<String> l2=Arrays.asList("1", "3");
		mDequeue.addAll(l);
		assertEquals(mDequeue, l);
		mDequeue.removeIf((v) -> Integer.parseInt(v)%2==0);
		assertNotEquals(mDequeue, l);
		assertEquals(mDequeue, l2);
	}
	@Test
	public void testMultipleIterator(){
		for(int i = 0; i < MAX_PROBLEM_SIZE/1000; i++){

			mDequeue = getDequeueInstance();
			for(int j = 0; j < i; j++){
				mDequeue.addLast( String.valueOf(j) );
			}

			@SuppressWarnings("rawtypes")
			Iterator[] someIterators = {
					mDequeue.iterator(),
					mDequeue.iterator(),
					mDequeue.iterator(),
					mDequeue.iterator(),
					mDequeue.iterator(),
					mDequeue.iterator()
			};

			@SuppressWarnings("unchecked")
			Iterator<String>[] manyStringIterators =
					(Iterator<String>[]) someIterators;

			for(int iterID = 0; iterID < manyStringIterators.length; iterID++){
				int index = 0;
				while( manyStringIterators[iterID].hasNext() ){
					assertEquals( manyStringIterators[iterID].next(),String.valueOf(index),
							"Iterator #" + iterID + " failed:\n");
					index++;
				}
			}

		}
	}

	@Test
	public void testQueueBehavior(){

		String[] aBunchOfString = {
				"One", "Two", "Three", "Four"
		};

		for(String aString : aBunchOfString){
			mDequeue.addFirst(aString);
		}

		for(String aString : aBunchOfString){
			assertEquals(aString, mDequeue.removeLast());
		}
	}

	@Test
	public void testStackBehavior(){

		String[] aBunchOfString = {
				"One", "Two", "Three", "Four"
		};

		for(String aString : aBunchOfString){
			mDequeue.addFirst(aString);
		}

		for(int i = aBunchOfString.length - 1; i >= 0; i--){
			assertEquals(mDequeue.removeFirst(), aBunchOfString[i]);
		}
	}
}

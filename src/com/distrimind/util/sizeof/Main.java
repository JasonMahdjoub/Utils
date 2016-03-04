package com.distrimind.util.sizeof;

import java.util.ArrayList;

public class Main
{
    static class truc
    {
	@SuppressWarnings("unused")
	private int a=0;
	private ArrayList<Float> v=new ArrayList<Float>();
	
	truc()
	{
	    for (int i=0;i<10;i++)
	    {
		v.add(new Float(0));
	    }
	}
    }
    static class truc1
    {
	@SuppressWarnings("unused")
	private int a=0;
	@DontComputeSize(depth=1)
	private ArrayList<Float> v=new ArrayList<Float>();
	
	truc1()
	{
	    for (int i=0;i<10;i++)
	    {
		v.add(new Float(0));
	    }
	}
    }
    static class truc2
    {
	@SuppressWarnings("unused")
	private int a=0;
	@DontComputeSize(depth=2)
	private ArrayList<Float> v=new ArrayList<Float>();
	
	truc2()
	{
	    for (int i=0;i<10;i++)
	    {
		v.add(new Float(0));
	    }
	}
    }
    static class truc3
    {
	@SuppressWarnings("unused")
	private int a=0;
	@DontComputeSizeForInnerCollectionElements
	private ArrayList<Float> v=new ArrayList<Float>();
	
	truc3()
	{
	    for (int i=0;i<10;i++)
	    {
		v.add(new Float(0));
	    }
	}
	
    }
    static class bidule
    {
	public int truc[]=new int[1];
    }
    public static void main(String args[]) throws SecurityException
    {
	truc t=new truc();
	truc1 t1=new truc1();
	truc2 t2=new truc2();
	truc3 t3=new truc3();
	System.out.println(ObjectSizer.sizeOf(t));
	System.out.println(ObjectSizer.sizeOf(t1));
	System.out.println(ObjectSizer.sizeOf(t2));
	System.out.println(ObjectSizer.sizeOf(t3));
	System.out.println(ObjectSizer.sizeOf(2));
    }
    
}


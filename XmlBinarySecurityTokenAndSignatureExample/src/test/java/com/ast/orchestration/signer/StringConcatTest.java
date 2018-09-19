package com.ast.orchestration.signer;

import java.util.Calendar;

import org.junit.Test;

public class StringConcatTest {

	private static final String LONG_LINE = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Quisque placerat metus.";

	@Test
	public void test() {
		long time1 = Calendar.getInstance().getTime().getTime();
		System.out.println("time1: " + time1);
		String result = "";
		int numItems = 25000;
		for (int i = 0; i < numItems; i++)
			result += LONG_LINE; // String concatenation
		result.toString();
		long time2 = Calendar.getInstance().getTime().getTime();
		System.out.println("time2: " + time2);
		System.out.println("String concat time: " + (time2 - time1));
		System.out.println();

		// StringBuilder b = new StringBuilder(numItems * "This is a long line".length());
		StringBuilder b = new StringBuilder();
		for (int i = 0; i < numItems; i++)
			b.append(LONG_LINE);
		b.toString();
		long time3 = Calendar.getInstance().getTime().getTime();
		System.out.println("time3: " + time3);
		System.out.println("StringBuilder time: " + (time3 - time2));
		System.out.println();

		Object[] strings = new Object[numItems];
		StringBuilder formatTemplate = new StringBuilder();
		for (int i = 0; i < numItems; i++) {
			strings[i] = LONG_LINE;
			formatTemplate.append("%s ");
		}
		String template = formatTemplate.toString();
		long time4 = Calendar.getInstance().getTime().getTime();
		System.out.println("time4: " + time4);
		result = String.format(template, strings);
		long time5 = Calendar.getInstance().getTime().getTime();
		System.out.println("time5: " + time5);
		System.out.println("String.format time: " + (time5 - time4));
		System.out.println();
	}

}

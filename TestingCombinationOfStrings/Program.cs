using System;
using System.Collections.Generic;
using System.Linq;

public class CombinationGenerator
{
	public static List<List<string>> GenerateCombinations(List<string> items, int combinationSize)
	{
		if (items == null || combinationSize <= 0 || combinationSize > items.Count)
			throw new ArgumentException("Invalid input: Ensure the list is not null and the combination size is valid.");

		var result = new List<List<string>>();
		GenerateCombinationsRecursive(items, combinationSize, 0, new List<string>(), result);
		return result;
	}

	private static void GenerateCombinationsRecursive(List<string> items, int combinationSize, int start, List<string> current, List<List<string>> result)
	{
		if (current.Count == combinationSize)
		{
			result.Add(new List<string>(current));
			return;
		}

		for (int i = start; i < items.Count; i++)
		{
			current.Add(items[i]);
			GenerateCombinationsRecursive(items, combinationSize, i + 1, current, result);
			current.RemoveAt(current.Count - 1);
		}
	}

	public static void Main(string[] args)
	{
		var items = new List<string> { "B", "A", "C" };
		items.Sort();
		int combinationSize = 2;

		try
		{
			var combinations = GenerateCombinations(items, combinationSize);

			Console.WriteLine("Combinations:");
			foreach (var combination in combinations)
			{
				Console.WriteLine(string.Join(", ", combination));
			}
		}
		catch (Exception ex)
		{
			Console.WriteLine($"Error: {ex.Message}");
		}
	}
}

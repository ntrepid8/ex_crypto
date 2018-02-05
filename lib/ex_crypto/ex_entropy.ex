defmodule ExEntropy do
  @doc """
  Compute the Shannon entropy of a binary value.

  reference:

  - <http://stackoverflow.com/questions/990477/how-to-calculate-the-entropy-of-a-file>
  - <https://en.wikipedia.org/wiki/Entropy_(information_theory)>
  """
  @spec shannon_entropy(binary, integer) :: float
  def shannon_entropy(value, exponent) when is_binary(value) do
    # convert the binary value into a list with exponent as one of [1, 8]
    val_list = gen_val_list(value, exponent)

    val_range = round(:math.pow(2, exponent) - 1)
    val_accumulator = for x <- 0..val_range, into: %{}, do: {x, 0}

    # accumulate occurrence counts
    accumulated_occurances = count_occurances(val_accumulator, val_list)

    # transform the map of occurrence counts into a list
    ao_list = Enum.map(accumulated_occurances, fn {_k, v} -> v end)

    # compute Shannon's entropy
    shannon_entropy_0(0, length(val_list), length(ao_list), ao_list)
  end

  def shannon_entropy(value) when is_binary(value) do
    # byte blocks by default
    shannon_entropy(value, 8)
  end

  defp shannon_entropy_0(entropy, _block_count, _block_range, []) do
    entropy
  end

  defp shannon_entropy_0(entropy, block_count, block_range, [h | t]) do
    case h do
      0 ->
        shannon_entropy_0(entropy, block_count, block_range, t)

      _ ->
        p = 1.0 * h / block_count
        udpated_entropy = entropy - p * (:math.log(p) / :math.log(block_range))
        shannon_entropy_0(udpated_entropy, block_count, block_range, t)
    end
  end

  defp count_occurances(accumulator, []) do
    accumulator
  end

  defp count_occurances(accumulator, [h | t]) do
    c_0 = Map.get(accumulator, h, 0)
    count_occurances(Map.put(accumulator, h, c_0 + 1), t)
  end

  defp gen_val_list(value, exponent) do
    case exponent do
      # bits
      1 ->
        for <<x::1 <- value>>, do: x

      # bytes
      8 ->
        for <<x::8 <- value>>, do: x

      # kilobytes
      10 ->
        for <<x::10 <- value>>, do: x

      # hex
      16 ->
        for <<x::16 <- value>>, do: x

      # megabytes
      20 ->
        for <<x::20 <- value>>, do: x
    end
  end
end

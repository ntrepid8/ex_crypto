defmodule ExEntropyTest do
  use ExUnit.Case

  defp generate_repeat_list(accumulator, value, count) when is_list(accumulator) do
    case count do
      c when c >= 0 ->
        generate_repeat_list(List.insert_at(accumulator, -1, value), value, count - 1)

      c when c < 0 ->
        accumulator
    end
  end

  defp generate_repeat_list(value, count) do
    generate_repeat_list([], value, count)
  end

  test "shannon_entropy with strong_rand_bytes and 2^8" do
    rand_bytes = :crypto.strong_rand_bytes(1024)
    shannon_entropy = ExEntropy.shannon_entropy(rand_bytes, 8)
    assert(shannon_entropy > 0.97)
  end

  test "shannon_entropy with strong_rand_bytes and 2^1" do
    rand_bytes = :crypto.strong_rand_bytes(1024)
    shannon_entropy = ExEntropy.shannon_entropy(rand_bytes, 1)
    assert(shannon_entropy > 0.99)
  end

  test "shannon_entropy with strong_rand_bytes and 2^10" do
    rand_bytes = :crypto.strong_rand_bytes(1024 * 1000)
    shannon_entropy = ExEntropy.shannon_entropy(rand_bytes, 10)
    assert(shannon_entropy > 0.99)
  end

  test "shannon_entropy with strong_rand_bytes and 2^16" do
    rand_bytes = :crypto.strong_rand_bytes(1024 * 1000)
    shannon_entropy = ExEntropy.shannon_entropy(rand_bytes, 16)
    assert(shannon_entropy > 0.99)
  end

  test "shannon_entropy with strong_rand_bytes and 2^20" do
    rand_bytes = :crypto.strong_rand_bytes(1024 * 1000)
    shannon_entropy = ExEntropy.shannon_entropy(rand_bytes, 20)
    # this is taxing on the entropy pool
    assert(shannon_entropy > 0.90)
  end

  test "shannon_entropy with known low entropy bytes and 2^8" do
    # generate two random bytes
    {:ok, bin_val_0} = ExCrypto.rand_bytes(1)
    {:ok, bin_val_1} = ExCrypto.rand_bytes(1)

    # use the two random numbers to generate a low entropy binary string
    bytes_val_2 =
      Enum.join(generate_repeat_list(bin_val_0, 127)) <>
        Enum.join(generate_repeat_list(bin_val_1, 127))

    assert(is_binary(bytes_val_2))
    assert(byte_size(bytes_val_2) == 256)

    # measure the entropy in the low entropy string and assert it is low
    entropy = ExEntropy.shannon_entropy(bytes_val_2, 8)

    # a 256 byte binary string with 2 unique values has a Shannon's entropy 
    # value of 0.125 when calculated with 1 byte blocks
    assert(entropy < 0.126)
  end

  test "shannon_entropy with known low entropy bytes and 2^1" do
    # generate two random bytes
    {:ok, bin_val_0} = ExCrypto.rand_bytes(1)
    {:ok, bin_val_1} = ExCrypto.rand_bytes(1)

    # use the two random numbers to generate a low entropy binary string
    bytes_val_2 =
      Enum.join(generate_repeat_list(bin_val_0, 127)) <>
        Enum.join(generate_repeat_list(bin_val_1, 127))

    assert(is_binary(bytes_val_2))
    assert(byte_size(bytes_val_2) == 256)

    # measure the entropy in the low entropy string and assert it is low
    entropy_1 = ExEntropy.shannon_entropy(bytes_val_2, 1)

    # a 256 byte binary string with 2 unique values has a Shannon's entropy 
    # value of much more than 0.125
    assert(entropy_1 > 0.126)

    # in fact, for 2^x where x is 1 the same sort of value looks almost ok
    assert(entropy_1 > 0.65)

    # entropy_1 probably does not reach extremely high confidence
    # it could happen if the number of `0`s was almost exactly the same as the number of `1`s
    # so this assertion may fail occasionally, but it illustrates why 1-bit block sizes should not be used
    if entropy_1 > 0.99 do
      # patterns are more likely to be detectable using full bytes
      entropy_8 = ExEntropy.shannon_entropy(bytes_val_2, 8)
      assert(entropy_8 < 0.126)
    end
  end

end

defmodule ExCryptoTest do
  use ExUnit.Case

  test "the truth" do
    assert 1 + 1 == 2
  end

  def run_rand_char_test() do
    rand_char_count = :crypto.rand_uniform(1, 100)
    rand_string = ExCrypto.rand_chars(rand_char_count)
    assert(String.length(rand_string) == rand_char_count)
  end
  
  test "generate random characters" do
    for n <- 1..100, do: run_rand_char_test()
  end

  test "generate random integers and test randomness" do
    set_size = 100000
    random_ints = for n <- 1..set_size, do: ExCrypto.rand_int(1, 100)

    # do cursory check for randomness, average should be very near 50
    average = Enum.sum(random_ints) / set_size
    assert(average > 49.5)
    assert(average < 50.5)
  end

end

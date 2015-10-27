defmodule ExEntropyTest do
  use ExUnit.Case

  test "validate entropy in binary" do 
    {:ok, bin_val} = ExCrypto.rand_bytes(16)
    ExEntropy.measure_entropy(bin_val)
  end
end
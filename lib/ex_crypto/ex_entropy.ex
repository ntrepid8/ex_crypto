defmodule ExEntropy do

  def measure_entropy(value) when is_binary(value) do
    byte_length = byte_size(value)
    bit_list = for << a::1 <- value >>, do: a
    bit_count = length(bit_list)
    IO.puts bit_count
    bit_sum = sum_list(bit_list)
    IO.puts bit_sum
    bit_entropy = bit_sum / bit_count
    IO.puts "bit_entropy: #{bit_entropy}"

    # byte entropy
    byte_list = for << a::8 <- value >>, do: a
    IO.puts byte_list
    byte_sums = for x <- 1..255, do: byte_count(x, byte_list) 
    IO.puts "byte_sums: #{byte_sums}"
  end

  defp sum_list([]) do
    0
  end

  defp sum_list([h|t]) do
    h + sum_list(t)
  end

  def byte_count(target, []) do
    0
  end

  def byte_count(target, [h|t]) do
    # IO.puts "target?: #{target} == #{h}"
    case h do
      target -> 
        # IO.puts "byte_count_match: #{target}"
        1 + byte_count(target, t)
      _ -> 
        0 + byte_count(target, t)
    end
  end

end
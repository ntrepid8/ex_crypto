defmodule ExCrypto do

  defmacro __using__(_) do
    quote do
      import ExCrypto
    end
  end

  use Pipe

  def normalize_error(kind, error) do
    case Exception.normalize(kind, error) do
      %{message: message} ->
        {:error, message}
      x ->
        {kind, x, System.stacktrace}
    end
  end

  @doc """
  Returns random characters in "blocks". Each block is a string 
  of 4 chars.  Each block represents 24 bits of entropy, base64 encoded.

  Useful for generating unique strings for use in file names.
  """
  @spec rand_chars(Integer.t) :: String.t
  def rand_chars(num_chars) do
    block_bytes = 3
    block_chars = 4
    block_count = div(num_chars, block_chars)
    block_partial = rem(num_chars, block_chars)
    if block_partial > 0 do
      block_count = block_count + 1
    end
    rand_string = Base.url_encode64(:crypto.strong_rand_bytes(block_count * block_bytes))
    String.slice(rand_string, 0, num_chars)
  end

  @spec rand_int(integer, integer) :: integer
  def rand_int(low, high) do
    :crypto.rand_uniform(low, high)
  end

  def rand_bytes(length) do
    {:ok, :crypto.strong_rand_bytes(length)}
  catch
    kind, error -> ExPublicKey.normalize_error(kind, error)
  end

  def generate_aes_key(key_type, key_format) do
    case {key_type, key_format} do
      {:aes_128, :base64} -> pipe_ok rand_bytes(128) |> url_encode64
      {:aes_128, :bytes} -> rand_bytes(128)
      {:aes_192, :base64} -> pipe_ok rand_bytes(192) |> url_encode64
      {:aes_192, :bytes} -> rand_bytes(192)
      {:aes_256, :base64} -> pipe_ok rand_bytes(256) |> url_encode64
      {:aes_256, :bytes} -> rand_bytes(256)
      _ -> {:error, "invalid key_type/key_format"}
    end
  end

  defp url_encode64(bytes_to_encode) do
    {:ok, Base.url_encode64(bytes_to_encode)}
  end

  defp pipe_ok(chain) do
    pipe_matching x, {:ok, x}, chain
  end

end

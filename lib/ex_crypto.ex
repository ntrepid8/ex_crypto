defmodule ExCrypto do
  @moduledoc """
  The ExCrypto module exposes a subset of functionality from the Erlang `crypto` 
  module with the goal of making it easier to include strong cryptography in your
  Elixir applications.

  This module provides functions for symmetric-key cryptographic operations using 
  AES in GCM mode. The ExCrypto module attempts to reduce complexity by providing 
  some sane default values for common operations.
  """

  defmacro __using__(_) do
    quote do
      import ExCrypto
    end
  end

  use Pipe

  defmacrop pipe_ok(pipes) do
    quote do
      pipe_matching(x, {:ok, x}, unquote(pipes))
    end
  end

  defp normalize_error(kind, error) do
    case Exception.normalize(kind, error) do
      %{message: message} ->
        {:error, message}
      x ->
        {kind, x, System.stacktrace}
    end
  end

  defp detail_normalize_error(kind, error) do
    {kind, Exception.normalize(kind, error), System.stacktrace}
  end

  @doc """
  Returns random characters. Each character represents 6 bits of entropy.

  Accepts an `integer` to determine the number of random characters to return.

  ## Examples

      iex> ExCrypto.rand_chars(10)
      "vIS7PHrDD_"
  """
  @spec rand_chars(integer) :: String.t
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

  @doc """
  Returns a random integer between `low` and `high`.

  Accepts two `integer` arguments for the `low` and `high` boundaries. The `low` argument 
  must be less than the `high` argument.

  ## Examples

      iex> ExCrypto.rand_int(5, 15)
      13
  """
  @spec rand_int(integer, integer) :: integer
  def rand_int(low, high) do
    :crypto.rand_uniform(low, high)
  end

  @doc """
  Returns a string of random where the length is equal to `integer`.

  ## Examples

      iex> ExCrypto.rand_int(2, 20)
      18
      iex> ExCrypto.rand_int(2, 20)
      4
      iex> ExCrypto.rand_int(2, 20)
      6
  """
  @spec rand_bytes(integer) :: {:ok, binary} | {:error, binary}
  def rand_bytes(length) do
    {:ok, :crypto.strong_rand_bytes(length)}
  catch
    kind, error -> ExPublicKey.normalize_error(kind, error)
  end

  @doc """
  Returns an AES key.

  Accepts a `key_type` (`:aes_128`|`:aes_192`|`:aes_256`) and `key_format` 
  (`:base64`|`:bytes`) to determine type of key to produce.

  ## Examples

      iex> ExCrypto.generate_aes_key(:aes_256, :base64)
      {:ok, "fvguC4ig4gCKQfrfQ9L3afLBJdjabA1e6iNH2oBEuTU="}

      iex> ExCrypto.generate_aes_key(:aes_256, :bytes)
      {:ok,
       <<181, 0, 19, 108, 87, 27, 143, 104, 195, 215, 160, 141, 42, 246, 248, 231, 135, 58, 179, 251, 211, 110, 78, 35, 214, 167, 233, 184, 86, 151, 53, 79>>}

      iex> ExCrypto.generate_aes_key(:aes_192, :base64)
      {:ok, "itsyAgZ2zwF0j9p8WhAXsAyKPNyFsbF3"}
      
      iex> ExCrypto.generate_aes_key(:aes_192, :bytes)
      {:ok,
       <<174, 156, 244, 175, 90, 157, 206, 70, 58, 9, 244, 202, 243, 192, 138, 177, 30, 164, 152, 27, 106, 160, 251, 46>>}

      iex> ExCrypto.generate_aes_key(:aes_128, :base64)
      {:ok, "Gh2ahuaKED2gfw0I2k4Sbw=="}
      
      iex> ExCrypto.generate_aes_key(:aes_128, :bytes)
      {:ok,
       <<141, 112, 245, 211, 119, 226, 108, 244, 23, 180, 228, 69, 47, 162, 221, 10>>}

  """
  @spec generate_aes_key(atom, atom) :: {:ok, binary} | {:error, binary}
  def generate_aes_key(key_type, key_format) do
    case {key_type, key_format} do
      {:aes_128, :base64} -> pipe_ok rand_bytes(16) |> url_encode64
      {:aes_128, :bytes} -> rand_bytes(16)
      {:aes_192, :base64} -> pipe_ok rand_bytes(24) |> url_encode64
      {:aes_192, :bytes} -> rand_bytes(24)
      {:aes_256, :base64} -> pipe_ok rand_bytes(32) |> url_encode64
      {:aes_256, :bytes} -> rand_bytes(32)
      _ -> {:error, "invalid key_type/key_format"}
    end
  end

  defp url_encode64(bytes_to_encode) do
    {:ok, Base.url_encode64(bytes_to_encode)}
  end

  @doc """
  Returns a cipher-text string encrypted with AES in GCM mode.
  """
  @spec encrypt(binary, binary, binary, binary) :: {:ok, binary} | {:error, binary}
  def encrypt(key, initialization_vector, authentication_data, clear_text) do
    {:ok, :crypto.block_encrypt(:aes_gcm, key, initialization_vector, {authentication_data, clear_text})}
  catch
    kind, error -> normalize_error(kind, error)
  end

  @doc """
  Returns a clear-text string decrypted with AES in GCM mode.
  """
  @spec decrypt(binary, binary, binary, binary, binary) :: {:ok, binary} | {:error, binary}
  def decrypt(key, initialization_vector, authentication_data, cipher_text, cipher_tag) do
    {:ok, :crypto.block_decrypt(:aes_gcm, key, initialization_vector, {authentication_data, cipher_text, cipher_tag})}
  catch
    kind, error -> normalize_error(kind, error)
  end

end

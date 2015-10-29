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

      iex> ExCrypto.rand_chars(24)
      "njZ7bbu6UmLbEtw5JpaKGd4s"
      iex> ExCrypto.rand_chars(32)
      "Mk7I3SMCz2kKMUFYZcch7X-yFl2AjUGa"
      iex> ExCrypto.rand_chars(44)
      "9KS1uHmFBfZB4wFdPmnapw4mi7lpuVuixSuezcIn-YOe"
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

      iex> ExCrypto.rand_int(2, 20)
      18
      iex> ExCrypto.rand_int(2, 20)
      4
      iex> ExCrypto.rand_int(2, 20)
      6
  """
  @spec rand_int(integer, integer) :: integer
  def rand_int(low, high) do
    :crypto.rand_uniform(low, high)
  end

  @doc """
  Returns a string of random where the length is equal to `integer`.

  ## Examples

      iex> ExCrypto.rand_bytes(16)
      {:ok,
       <<57, 120, 189, 13, 191, 164, 215, 31, 182, 64, 145, 125, 64, 149, 223, 243>>}
      iex> ExCrypto.rand_bytes(24)
      {:ok,
       <<190, 157, 28, 47, 167, 217, 199, 159, 188, 20, 29, 8, 209, 146, 104, 200, 210, 100, 115, 143, 157, 20, 196, 69>>}
      iex> ExCrypto.rand_bytes(32)
      {:ok,
       <<64, 200, 58, 1, 149, 140, 63, 2, 50, 188, 216, 210, 42, 25, 163, 194, 31, 92, 234, 182, 242, 201, 113, 12, 240, 105, 231, 47, 113, 31, 217, 199>>}
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
  Encrypt a `binary` with AES in GCM mode.

  Returns a tuple containing the `initialization_vector`, the `cipher_text` and the `cipher_tag`.

  At a high level encryption using AES in GCM mode looks like this:

      key + init_vec + auth_data + clear_text -> cipher_text + cipher_tag

  ## Examples

      iex> {:ok, aes_256_key} = ExCrypto.generate_aes_key(:aes_256, :bytes)
      {:ok,
       <<102, 61, 103, 218, 73, 12, 233, 190, 254, 123, 108, 9, 230, 183, 7, 46, 233, 75, 1, 147, 143, 167, 78, 232, 126, 187, 153, 239, 128, 133, 76, 25>>}
      
      iex> {:ok, iv} = ExCrypto.rand_bytes(16)
      {:ok,
       <<137, 18, 92, 222, 46, 164, 131, 171, 232, 216, 144, 51, 227, 240, 186, 116>>}
      
      iex> {:ok, {iv, cipher_text, cipher_tag}} = ExCrypto.encrypt(aes_256_key, "my-auth-data", iv, "my-clear-text")
      {:ok,
       {"my-auth-data",
        <<137, 18, 92, 222, 46, 164, 131, 171, 232, 216, 144, 51, 227, 240, 186, 116>>,
        <<242, 162, 159, 156, 28, 117, 128, 247, 48, 128, 25, 47, 151>>,
        <<160, 113, 232, 103, 162, 0, 75, 69, 31, 50, 186, 213, 72, 239, 229, 208>>}}


  """
  @spec encrypt(binary, binary, binary, binary) :: {:ok, {binary, binary, binary, binary}} | {:error, binary}
  def encrypt(key, authentication_data, initialization_vector, clear_text) do
    case :crypto.block_encrypt(:aes_gcm, key, initialization_vector, {authentication_data, clear_text}) do
      {cipher_text, cipher_tag} -> {:ok, {authentication_data, initialization_vector, cipher_text, cipher_tag}}
      x -> {:error, x}
    end
  catch
    kind, error -> normalize_error(kind, error)
  end

  @doc """
  Encrypt a `binary` with AES in GCM mode.

  A 128 bit `initialization_vector` is generated automatically by `encrypt/3`. It returns a tuple 
  containing the `initialization_vector`, the `cipher_text` and the `cipher_tag`.

  ## Examples

      iex> {:ok, aes_256_key} = ExCrypto.generate_aes_key(:aes_256, :bytes)
      {:ok,
       <<94, 197, 140, 75, 88, 191, 233, 230, 189, 96, 86, 107, 179, 243, 111, 10, 201, 22, 84, 219, 90, 70, 107, 225, 13, 196, 147, 56, 34, 33, 22, 107>>}
      
      iex> {:ok, {iv, cipher_text, cipher_tag}} = ExCrypto.encrypt(aes_256_key, "my-auth-data", "my-clear-text")
      {:ok,
       {"my-auth-data",
        <<11, 186, 216, 183, 181, 243, 68, 244, 207, 146, 117, 130, 3, 59, 190, 68>>,
        <<57, 186, 115, 169, 171, 156, 120, 252, 200, 124, 218, 194, 216>>,
        <<148, 154, 168, 69, 139, 255, 61, 31, 203, 159, 224, 13, 50, 92, 152, 32>>}}

  """
  @spec encrypt(binary, binary, binary) :: {:ok, {binary, binary, binary, binary}} | {:error, binary}
  def encrypt(key, authentication_data, clear_text) do
    {:ok, initialization_vector} = rand_bytes(16)  # new 128 bit random initialization_vector
    encrypt(key, authentication_data, initialization_vector, clear_text)
  end

  @doc """
  Returns a clear-text string decrypted with AES in GCM mode.

  At a high level decryption using AES in GCM mode looks like this:

      key + init_vec + auth_data + cipher_text + cipher_tag -> clear_text

  ## Examples

      iex> {:ok, aes_256_key} = ExCrypto.generate_aes_key(:aes_256, :bytes)
      {:ok,
       <<94, 197, 140, 75, 88, 191, 233, 230, 189, 96, 86, 107, 179, 243, 111, 10, 201, 22, 84, 219, 90, 70, 107, 225, 13, 196, 147, 56, 34, 33, 22, 107>>}
      
      iex> {:ok, {iv, cipher_text, cipher_tag}} = ExCrypto.encrypt(aes_256_key, "my-auth-data", "my-clear-text")
      {:ok,
       {<<11, 186, 216, 183, 181, 243, 68, 244, 207, 146, 117, 130, 3, 59, 190, 68>>,
        <<57, 186, 115, 169, 171, 156, 120, 252, 200, 124, 218, 194, 216>>,
        <<148, 154, 168, 69, 139, 255, 61, 31, 203, 159, 224, 13, 50, 92, 152, 32>>}}

      iex> ExCrypto.decrypt(aes_256_key, "my-auth-data", iv, cipher_text, cipher_tag)
      {:ok, "my-clear-text"}

  """
  @spec decrypt(binary, binary, binary, binary, binary) :: {:ok, binary} | {:error, binary}
  def decrypt(key, authentication_data, initialization_vector, cipher_text, cipher_tag) do
    {:ok, :crypto.block_decrypt(:aes_gcm, key, initialization_vector, {authentication_data, cipher_text, cipher_tag})}
  catch
    kind, error -> normalize_error(kind, error)
  end

  def encode_payload(initialization_vector, cipher_text, cipher_tag) do
    {:ok, encoded_parts} = url_encode64(initialization_vector <> cipher_text <> cipher_tag)
    {:ok, encoded_parts}
  end

  def decode_payload(encoded_parts) do
    {:ok, decoded_parts} = Base.url_decode64(encoded_parts)
    decoded_length = byte_size(decoded_parts)
    iv = Kernel.binary_part(decoded_parts, 0, 16)
    cipher_text = Kernel.binary_part(decoded_parts, 16, (decoded_length-32))
    cipher_tag = Kernel.binary_part(decoded_parts, decoded_length, -16)
    {:ok, {iv, cipher_text, cipher_tag}}
  end

end

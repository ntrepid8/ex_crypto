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

      iex> rand_string = ExCrypto.rand_chars(24)
      iex> assert(String.length(rand_string) == 24)
      true
      
      iex> rand_string = ExCrypto.rand_chars(32)
      iex> assert(String.length(rand_string) == 32)
      true
      
      iex> rand_string = ExCrypto.rand_chars(44)
      iex> assert(String.length(rand_string) == 44)
      true
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

      iex> rand_int = ExCrypto.rand_int(2, 20)
      iex> assert(rand_int > 1)
      true
      iex> assert(rand_int < 21)
      true
      
      iex> rand_int = ExCrypto.rand_int(23, 99)
      iex> assert(rand_int > 22)
      true
      iex> assert(rand_int < 99)
      true
      
      iex> rand_int = ExCrypto.rand_int(212, 736)
      iex> assert(rand_int > 211)
      true
      iex> assert(rand_int < 737)
      true
  """
  @spec rand_int(integer, integer) :: integer
  def rand_int(low, high) do
    :crypto.rand_uniform(low, high)
  end

  @doc """
  Returns a string of random where the length is equal to `integer`.

  ## Examples

      iex> {:ok, rand_bytes} = ExCrypto.rand_bytes(16)
      iex> assert(byte_size(rand_bytes) == 16)
      true
      iex> assert(bit_size(rand_bytes) == 128)
      true
      
      iex> {:ok, rand_bytes} = ExCrypto.rand_bytes(24)
      iex> assert(byte_size(rand_bytes) == 24)
      true
      iex> assert(bit_size(rand_bytes) == 192)
      true

      iex> {:ok, rand_bytes} = ExCrypto.rand_bytes(32)
      iex> assert(byte_size(rand_bytes) == 32)
      true
      iex> assert(bit_size(rand_bytes) == 256)
      true
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

      iex> {:ok, key} = ExCrypto.generate_aes_key(:aes_256, :bytes)
      iex> assert bit_size(key) == 256
      true

      iex> {:ok, key} = ExCrypto.generate_aes_key(:aes_256, :base64)
      iex> assert String.length(key) == 44
      true

      iex> {:ok, key} = ExCrypto.generate_aes_key(:aes_192, :bytes)
      iex> assert bit_size(key) == 192
      true

      iex> {:ok, key} = ExCrypto.generate_aes_key(:aes_192, :base64)
      iex> assert String.length(key) == 32
      true
      
      iex> {:ok, key} = ExCrypto.generate_aes_key(:aes_128, :bytes)
      iex> assert bit_size(key) == 128
      true

      iex> {:ok, key} = ExCrypto.generate_aes_key(:aes_128, :base64)
      iex> assert String.length(key) == 24
      true
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

      iex> clear_text = "my-clear-text"
      iex> auth_data = "my-auth-data"
      iex> {:ok, aes_256_key} = ExCrypto.generate_aes_key(:aes_256, :bytes)
      iex> {:ok, iv} = ExCrypto.rand_bytes(16)
      iex> {:ok, {ad, payload}} = ExCrypto.encrypt(aes_256_key, auth_data, iv, clear_text)
      iex> {iv, cipher_text, cipher_tag} = payload
      iex> assert(is_bitstring(cipher_text))
      true
      iex> assert(bit_size(cipher_tag) == 128)
      true

  """
  @spec encrypt(binary, binary, binary, binary) :: {:ok, {binary, {binary, binary, binary}}} | {:error, binary}
  def encrypt(key, authentication_data, initialization_vector, clear_text) do
    case :crypto.block_encrypt(:aes_gcm, key, initialization_vector, {authentication_data, clear_text}) do
      {cipher_text, cipher_tag} -> {:ok, {authentication_data, {initialization_vector, cipher_text, cipher_tag}}}
      x -> {:error, x}
    end
  catch
    kind, error -> normalize_error(kind, error)
  end

  @doc """
  Same as `encrypt/4` except the `initialization_vector` is automatically.

  A 128 bit `initialization_vector` is generated automatically by `encrypt/3`. It returns a tuple 
  containing the `initialization_vector`, the `cipher_text` and the `cipher_tag`.

  ## Examples

      iex> clear_text = "my-clear-text"
      iex> auth_data = "my-auth-data"
      iex> {:ok, aes_256_key} = ExCrypto.generate_aes_key(:aes_256, :bytes)
      iex> {:ok, {ad, payload}} = ExCrypto.encrypt(aes_256_key, auth_data, clear_text)
      iex> {init_vec, cipher_text, cipher_tag} = payload
      iex> assert(is_bitstring(cipher_text))
      true
      iex> assert(bit_size(cipher_tag) == 128)
      true

  """
  @spec encrypt(binary, binary, binary) :: {:ok, {binary, {binary, binary, binary}}} | {:error, binary}
  def encrypt(key, authentication_data, clear_text) do
    {:ok, initialization_vector} = rand_bytes(16)  # new 128 bit random initialization_vector
    encrypt(key, authentication_data, initialization_vector, clear_text)
  end

  @doc """
  Returns a clear-text string decrypted with AES in GCM mode.

  At a high level decryption using AES in GCM mode looks like this:

      key + init_vec + auth_data + cipher_text + cipher_tag -> clear_text

  ## Examples

      iex> clear_text = "my-clear-text"
      iex> auth_data = "my-auth-data"
      iex> {:ok, aes_256_key} = ExCrypto.generate_aes_key(:aes_256, :bytes)
      iex> {:ok, {ad, payload}} = ExCrypto.encrypt(aes_256_key, auth_data, clear_text)
      iex> {init_vec, cipher_text, cipher_tag} = payload
      iex> {:ok, val} = ExCrypto.decrypt(aes_256_key, auth_data, init_vec, cipher_text, cipher_tag)
      iex> assert(val == clear_text)
      true
  """
  @spec decrypt(binary, binary, binary, binary, binary) :: {:ok, binary} | {:error, binary}
  def decrypt(key, authentication_data, initialization_vector, cipher_text, cipher_tag) do
    {:ok, :crypto.block_decrypt(:aes_gcm, key, initialization_vector, {authentication_data, cipher_text, cipher_tag})}
  catch
    kind, error -> normalize_error(kind, error)
  end

  @doc """
  Join the three parts of an encrypted payload and encode using `Base.url_encode64`.

  This produces a Unicode `payload` string like this:

      init_vec   <> cipher_text <> cipher_tag
      [128 bits] <>  [?? bits]  <> [128 bits]

  This format is convenient to include in HTTP request bodies.  It can also be used with JSON transport formats.

  ## Examples

      iex> clear_text = "my-clear-text"
      iex> auth_data = "my-auth-data"
      iex> {:ok, aes_256_key} = ExCrypto.generate_aes_key(:aes_256, :bytes)
      iex> {:ok, {ad, {init_vec, cipher_text, cipher_tag}}} = ExCrypto.encrypt(aes_256_key, auth_data, clear_text)
      iex> {:ok, encoded_payload} = ExCrypto.encode_payload(init_vec, cipher_text, cipher_tag)
      iex> assert(String.valid?(encoded_payload))
      true
  """
  @spec encode_payload(binary, binary, binary) :: {:ok, binary} | {:error, binary}
  def encode_payload(initialization_vector, cipher_text, cipher_tag) do
    url_encode64(initialization_vector <> cipher_text <> cipher_tag)
  end

  @doc """
  Split and decode the three parts of an encrypted payload and encode using `Base.url_decode64`.

  ## Examples

      iex> clear_text = "my-clear-text"
      iex> auth_data = "my-auth-data"
      iex> {:ok, aes_256_key} = ExCrypto.generate_aes_key(:aes_256, :bytes)
      iex> {:ok, {ad, {init_vec, cipher_text, cipher_tag}}} = ExCrypto.encrypt(aes_256_key, auth_data, clear_text)
      iex> {:ok, encoded_payload} = ExCrypto.encode_payload(init_vec, cipher_text, cipher_tag)
      iex> assert(String.valid?(encoded_payload))
      true
      iex> {:ok, {d_init_vec, d_cipher_text, d_cipher_tag}} = ExCrypto.decode_payload(encoded_payload)
      iex> assert(d_init_vec == init_vec)
      true
      iex> assert(d_cipher_text == cipher_text)
      true
      iex> assert(d_cipher_tag == cipher_tag)
      true
  """
  @spec decode_payload(binary) :: {:ok, {binary, binary, binary}} | {:error, binary}
  def decode_payload(encoded_parts) do
    {:ok, decoded_parts} = Base.url_decode64(encoded_parts)
    decoded_length = byte_size(decoded_parts)
    iv = Kernel.binary_part(decoded_parts, 0, 16)
    cipher_text = Kernel.binary_part(decoded_parts, 16, (decoded_length-32))
    cipher_tag = Kernel.binary_part(decoded_parts, decoded_length, -16)
    {:ok, {iv, cipher_text, cipher_tag}}
  end

end

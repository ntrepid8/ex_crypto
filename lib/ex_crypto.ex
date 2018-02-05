defmodule ExCrypto do
  @moduledoc """
  The ExCrypto module exposes a subset of functionality from the Erlang `crypto`
  module with the goal of making it easier to include strong cryptography in your
  Elixir applications.

  This module provides functions for symmetric-key cryptographic operations using
  AES in GCM and CBC mode. The ExCrypto module attempts to reduce complexity by providing
  some sane default values for common operations.
  """
  @epoch :calendar.datetime_to_gregorian_seconds({{1970, 1, 1}, {0, 0, 0}})
  @aes_block_size 16
  @iv_bit_length 128
  @bitlength_error "IV must be exactly 128 bits and key must be exactly 128, 192 or 256 bits"
  defmacro __using__(_) do
    quote do
      import ExCrypto
    end
  end

  defp normalize_error(kind, error, key_and_iv \\ nil) do
    key_error = test_key_and_iv_bitlength(key_and_iv)

    cond do
      key_error ->
        key_error

      %{message: message} = Exception.normalize(kind, error) ->
        {:error, message}

      x = Exception.normalize(kind, error) ->
        {kind, x, System.stacktrace()}
    end
  end

  defp test_key_and_iv_bitlength(nil), do: nil

  defp test_key_and_iv_bitlength({_key, iv}) when bit_size(iv) != @iv_bit_length,
    do: {:error, @bitlength_error}

  defp test_key_and_iv_bitlength({key, _iv}) when rem(bit_size(key), 128) == 0, do: nil
  defp test_key_and_iv_bitlength({key, _iv}) when rem(bit_size(key), 192) == 0, do: nil
  defp test_key_and_iv_bitlength({key, _iv}) when rem(bit_size(key), 256) == 0, do: nil
  defp test_key_and_iv_bitlength({_key, _iv}), do: {:error, @bitlength_error}

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
  @spec rand_chars(integer) :: String.t()
  def rand_chars(num_chars) do
    block_bytes = 3
    block_chars = 4
    block_count = div(num_chars, block_chars)
    block_partial = rem(num_chars, block_chars)

    block_count =
      case block_partial > 0 do
        true -> block_count + 1
        false -> block_count
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
    low + :rand.uniform(high - low + 1) - 1
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

  @spec rand_bytes!(integer) :: binary
  def rand_bytes!(length) do
    case rand_bytes(length) do
      {:ok, data} -> data
      {:error, reason} -> raise reason
    end
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
      {:aes_128, :base64} -> rand_bytes!(16) |> url_encode64
      {:aes_128, :bytes} -> rand_bytes(16)
      {:aes_192, :base64} -> rand_bytes!(24) |> url_encode64
      {:aes_192, :bytes} -> rand_bytes(24)
      {:aes_256, :base64} -> rand_bytes!(32) |> url_encode64
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
      iex> {:ok, {_ad, payload}} = ExCrypto.encrypt(aes_256_key, auth_data, iv, clear_text)
      iex> {_iv, cipher_text, cipher_tag} = payload
      iex> assert(is_bitstring(cipher_text))
      true
      iex> assert(bit_size(cipher_tag) == 128)
      true

  """
  @spec encrypt(binary, binary, binary, binary) ::
          {:ok, {binary, {binary, binary, binary}}} | {:error, binary}
  def encrypt(key, authentication_data, initialization_vector, clear_text) do
    _encrypt(key, initialization_vector, {authentication_data, clear_text}, :aes_gcm)
  catch
    kind, error -> normalize_error(kind, error)
  end

  @doc """
  Encrypt a `binary` with AES in CBC mode.

  Returns a tuple containing the `initialization_vector`, and `cipher_text`.

  At a high level encryption using AES in CBC mode looks like this:

      key + clear_text -> init_vec + cipher_text

  ## Examples

      iex> clear_text = "my-clear-text"
      iex> {:ok, aes_256_key} = ExCrypto.generate_aes_key(:aes_256, :bytes)
      iex> {:ok, {_iv, cipher_text}} = ExCrypto.encrypt(aes_256_key, clear_text)
      iex> assert(is_bitstring(cipher_text))
      true

  """
  @spec encrypt(binary, binary) :: {:ok, {binary, binary}} | {:error, binary}
  def encrypt(key, clear_text) do
    # new 128 bit random initialization_vector
    {:ok, initialization_vector} = rand_bytes(16)
    _encrypt(key, initialization_vector, pad(clear_text, @aes_block_size), :aes_cbc256)
  catch
    kind, error ->
      {:ok, initialization_vector} = rand_bytes(16)
      normalize_error(kind, error, {key, initialization_vector})
  end

  @doc """
  Encrypt a `binary` with AES in CBC mode providing explicit IV via map.

  Returns a tuple containing the `initialization_vector`, and `cipher_text`.

  At a high level encryption using AES in CBC mode looks like this:

      key + clear_text + map -> init_vec + cipher_text

  ## Examples

      iex> clear_text = "my-clear-text"
      iex> {:ok, aes_256_key} = ExCrypto.generate_aes_key(:aes_256, :bytes)
      iex> {:ok, init_vec} = ExCrypto.rand_bytes(16)
      iex> {:ok, {_iv, cipher_text}} = ExCrypto.encrypt(aes_256_key, clear_text, %{initialization_vector: init_vec})
      iex> assert(is_bitstring(cipher_text))
      true

  """
  @spec encrypt(binary, binary, %{initialization_vector: binary}) ::
          {:ok, {binary, {binary, binary, binary}}}
          | {:ok, {binary, binary}}
          | {:error, any}
  def encrypt(key, clear_text, %{initialization_vector: initialization_vector}) do
    _encrypt(key, initialization_vector, pad(clear_text, @aes_block_size), :aes_cbc256)
  catch
    kind, error -> normalize_error(kind, error, {key, initialization_vector})
  end

  @doc """
  Same as `encrypt/4` except the `initialization_vector` is automatically generated.

  A 128 bit `initialization_vector` is generated automatically by `encrypt/3`. It returns a tuple
  containing the `initialization_vector`, the `cipher_text` and the `cipher_tag`.

  ## Examples

      iex> clear_text = "my-clear-text"
      iex> auth_data = "my-auth-data"
      iex> {:ok, aes_256_key} = ExCrypto.generate_aes_key(:aes_256, :bytes)
      iex> {:ok, {_ad, payload}} = ExCrypto.encrypt(aes_256_key, auth_data, clear_text)
      iex> {_init_vec, cipher_text, cipher_tag} = payload
      iex> assert(is_bitstring(cipher_text))
      true
      iex> assert(bit_size(cipher_tag) == 128)
      true

  """
  @spec encrypt(binary, binary, binary) ::
          {:ok, {binary, {binary, binary, binary}}} | {:error, binary}
  def encrypt(key, authentication_data, clear_text) do
    # new 128 bit random initialization_vector
    {:ok, initialization_vector} = rand_bytes(16)
    _encrypt(key, initialization_vector, {authentication_data, clear_text}, :aes_gcm)
  end

  defp _encrypt(key, initialization_vector, encryption_payload, algorithm) do
    case :crypto.block_encrypt(algorithm, key, initialization_vector, encryption_payload) do
      {cipher_text, cipher_tag} ->
        {authentication_data, _clear_text} = encryption_payload
        {:ok, {authentication_data, {initialization_vector, cipher_text, cipher_tag}}}

      <<cipher_text::binary>> ->
        {:ok, {initialization_vector, cipher_text}}

      x ->
        {:error, x}
    end
  end

  def pad(data, block_size) do
    to_add = block_size - rem(byte_size(data), block_size)
    data <> to_string(:string.chars(to_add, to_add))
  end

  def unpad(data) do
    to_remove = :binary.last(data)
    :binary.part(data, 0, byte_size(data) - to_remove)
  end

  @doc """
  Returns a clear-text string decrypted with AES in GCM mode.

  At a high level decryption using AES in GCM mode looks like this:

      key + init_vec + auth_data + cipher_text + cipher_tag -> clear_text

  ## Examples

      iex> clear_text = "my-clear-text"
      iex> auth_data = "my-auth-data"
      iex> {:ok, aes_256_key} = ExCrypto.generate_aes_key(:aes_256, :bytes)
      iex> {:ok, {_ad, payload}} = ExCrypto.encrypt(aes_256_key, auth_data, clear_text)
      iex> {init_vec, cipher_text, cipher_tag} = payload
      iex> {:ok, val} = ExCrypto.decrypt(aes_256_key, auth_data, init_vec, cipher_text, cipher_tag)
      iex> assert(val == clear_text)
      true
  """
  @spec decrypt(binary, binary, binary, binary, binary) :: {:ok, binary} | {:error, binary}
  def decrypt(key, authentication_data, initialization_vector, cipher_text, cipher_tag) do
    _decrypt(key, initialization_vector, {authentication_data, cipher_text, cipher_tag}, :aes_gcm)
  end

  @doc """
  Returns a clear-text string decrypted with AES256 in CBC mode.

  At a high level decryption using AES in CBC mode looks like this:

      key + init_vec + cipher_text  -> clear_text

  ## Examples

      iex> clear_text = "my-clear-text"
      iex> {:ok, aes_256_key} = ExCrypto.generate_aes_key(:aes_256, :bytes)
      iex> {:ok, {init_vec, cipher_text}} = ExCrypto.encrypt(aes_256_key, clear_text)
      iex> {:ok, val} = ExCrypto.decrypt(aes_256_key, init_vec, cipher_text)
      iex> assert(val == clear_text)
      true
  """
  @spec decrypt(binary, binary, binary) :: {:ok, binary} | {:error, binary}
  def decrypt(key, initialization_vector, cipher_text) do
    {:ok, padded_cleartext} = _decrypt(key, initialization_vector, cipher_text, :aes_cbc256)
    {:ok, unpad(padded_cleartext)}
  catch
    kind, error -> normalize_error(kind, error, {key, initialization_vector})
  end

  defp _decrypt(key, initialization_vector, cipher_data, algorithm) do
    {:ok, :crypto.block_decrypt(algorithm, key, initialization_vector, cipher_data)}
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
      iex> {:ok, {_ad, {init_vec, cipher_text, cipher_tag}}} = ExCrypto.encrypt(aes_256_key, auth_data, clear_text)
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
      iex> {:ok, {_ad, {init_vec, cipher_text, cipher_tag}}} = ExCrypto.encrypt(aes_256_key, auth_data, clear_text)
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
    cipher_text = Kernel.binary_part(decoded_parts, 16, decoded_length - 32)
    cipher_tag = Kernel.binary_part(decoded_parts, decoded_length, -16)
    {:ok, {iv, cipher_text, cipher_tag}}
  end

  @doc false
  def universal_time(:unix) do
    :calendar.datetime_to_gregorian_seconds(:calendar.universal_time()) - @epoch
  end
end

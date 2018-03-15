defmodule ExPublicKey do
  @moduledoc """
  API module for public-key infrastructure.

  ## Description

  Mostly wrappers Erlang' `:public_key` module, to help simplify using public/private key encryption in Elixir.
  """

  # Erlang public_key v1.4.1 corresponds to Erlang/OTP 20.0
  @otp_20_public_key_version [1, 4, 1]

  defmacro __using__(_) do
    quote do
      import ExPublicKey
      alias ExPublicKey.RSAPublicKey, as: RSAPublicKey
      alias ExPublicKey.RSAPrivateKey, as: RSAPrivateKey
    end
  end

  def normalize_error(kind, error) do
    case Exception.normalize(kind, error) do
      %{message: message} ->
        {:error, message}

      x ->
        {kind, x, System.stacktrace()}
    end
  end

  @doc """
  Loads PEM string from the specified file path and returns a `ExPublicKey.RSAPrivateKey` or a `ExPublicKey.RSAPublicKey` key.
  Optionally, a passphrase can be given to decode the PEM certificate.

  ## Examples
      {:ok, key} = ExPublicKey.load("/file/to/cert.pem")

      {:ok, key} = ExPublicKey.load("/file/to/cert.pem", "pem_password")

  """
  def load(file_path, passphrase \\ nil) do
    case File.read(file_path) do
      {:ok, key_string} ->
        ExPublicKey.loads(key_string, passphrase)

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Loads PEM string from the specified file path and returns a `ExPublicKey.RSAPrivateKey` or a `ExPublicKey.RSAPublicKey` key.
  Optionally, a passphrase can be given to decode the PEM certificate.
  Identical to `ExPublicKey.load/2`, except that load! raises an ExCrypto.Error when an exception occurs.

  ## Examples
      key = ExPublicKey.load("/file/to/cert.pem")

      key = ExPublicKey.load("/file/to/cert.pem", "pem_password")

  """
  def load!(file_path, passphrase \\ nil) do
    case load(file_path, passphrase) do
      {:ok, key} ->
        key

      {:error, reason} ->
        raise ExCrypto.Error, reason: reason
    end
  end

  defp validate_pem_length(pem_entries) do
    case length(pem_entries) do
      0 -> {:error, "invalid argument"}
      x when x > 1 -> {:error, "found multiple PEM entries, expected only 1"}
      x when x == 1 -> {:ok, Enum.at(pem_entries, 0)}
    end
  end

  @doc """
  Converts a PEM string into an `ExPublicKey.RSAPrivateKey` or an `ExPublicKey.RSAPublicKey` key.
  Optionally, a passphrase can be given to decode the PEM certificate.

  ## Examples
      {:ok, key} = ExPublicKey.loads(pem_string)

      {:ok, key} = ExPublicKey.loads(pem_string, "pem_password")

  """
  def loads(pem_string, passphrase \\ nil) do
    pem_entries = :public_key.pem_decode(pem_string)

    with {:ok, pem_entry} <- validate_pem_length(pem_entries),
         {:ok, rsa_key} <- load_pem_entry(pem_entry, passphrase),
         do: sort_key_tup(rsa_key)
  end

  @doc """
  Converts a PEM string into an `ExPublicKey.RSAPrivateKey` or an `ExPublicKey.RSAPublicKey` key.
  Identical to `ExPublicKey.loads/2`, except that loads! raises an ExCrypto.Error when an exception occurs.

  ## Example
      key = ExPublicKey.loads!(pem_string)

  """
  def loads!(pem_string, passphrase \\ nil) do
    case loads(pem_string, passphrase) do
      {:ok, key} ->
        key

      {:error, reason} ->
        raise ExCrypto.Error, reason: reason
    end
  end

  defp load_pem_entry(pem_entry, passphrase) do
    cond do
      is_binary(passphrase) ->
        load_pem_entry(pem_entry, String.to_charlist(passphrase))

      is_nil(passphrase) ->
        {:ok, :public_key.pem_entry_decode(pem_entry)}

      true ->
        {:ok, :public_key.pem_entry_decode(pem_entry, passphrase)}
    end
  catch
    kind, error ->
      ExPublicKey.normalize_error(kind, error)
  end

  defp sort_key_tup(key_tup) do
    case elem(key_tup, 0) do
      :RSAPrivateKey ->
        {:ok, ExPublicKey.RSAPrivateKey.from_sequence(key_tup)}

      :RSAPublicKey ->
        {:ok, ExPublicKey.RSAPublicKey.from_sequence(key_tup)}

      x ->
        {:error,
         "invalid argument, expected one of[ExPublicKey.RSAPublicKey, ExPublicKey.RSAPrivateKey], found: #{
           x
         }"}
    end
  end

  defp sign_0(rsa_priv_key_seq, msg, sha) do
    {:ok, :public_key.sign(msg, sha, rsa_priv_key_seq)}
  catch
    kind, error ->
      ExPublicKey.normalize_error(kind, error)
  end

  def sign(msg, sha, private_key) do
    with {:ok, priv_key_sequence} <- ExPublicKey.RSAPrivateKey.as_sequence(private_key),
         do: sign_0(priv_key_sequence, msg, sha)
  end

  def sign(msg, private_key) do
    ExPublicKey.sign(msg, :sha256, private_key)
  end

  defp verify_0(rsa_pub_key_seq, msg, sha, signature) do
    {:ok, :public_key.verify(msg, sha, signature, rsa_pub_key_seq)}
  catch
    kind, error -> ExPublicKey.normalize_error(kind, error)
  end

  def verify(msg, sha, signature, public_key) do
    with {:ok, pub_key_sequence} <- ExPublicKey.RSAPublicKey.as_sequence(public_key),
         do: verify_0(pub_key_sequence, msg, sha, signature)
  end

  def verify(msg, signature, public_key) do
    ExPublicKey.verify(msg, :sha256, signature, public_key)
  end

  defp encrypt_private_0(rsa_priv_key_seq, clear_text) do
    {:ok, :public_key.encrypt_private(clear_text, rsa_priv_key_seq)}
  catch
    kind, error ->
      ExPublicKey.normalize_error(kind, error)
  end

  def encrypt_private(clear_text, private_key, opts \\ []) do
    url_safe = Keyword.get(opts, :url_safe, true)

    with {:ok, priv_key_sequence} <- ExPublicKey.RSAPrivateKey.as_sequence(private_key),
         {:ok, cipher_bytes} <- encrypt_private_0(priv_key_sequence, clear_text),
         encoded_cipher_text = encode(cipher_bytes, url_safe),
         do: {:ok, encoded_cipher_text}
  end

  defp encrypt_public_0(rsa_pub_key_seq, clear_text) do
    {:ok, :public_key.encrypt_public(clear_text, rsa_pub_key_seq)}
  catch
    kind, error ->
      ExPublicKey.normalize_error(kind, error)
  end

  def encrypt_public(clear_text, public_key, opts \\ []) do
    url_safe = Keyword.get(opts, :url_safe, true)

    with {:ok, pub_key_sequence} <- ExPublicKey.RSAPublicKey.as_sequence(public_key),
         {:ok, cipher_bytes} <- encrypt_public_0(pub_key_sequence, clear_text),
         encoded_cipher_text = encode(cipher_bytes, url_safe),
         do: {:ok, encoded_cipher_text}
  end

  defp decrypt_private_0(cipher_bytes, private_key) do
    case ExPublicKey.RSAPrivateKey.as_sequence(private_key) do
      {:ok, rsa_priv_key_seq} -> {:ok, [cipher_bytes, rsa_priv_key_seq]}
      {:error, reason} -> {:error, reason}
    end
  end

  defp decrypt_private_1([cipher_bytes, rsa_priv_key_seq]) do
    {:ok, :public_key.decrypt_private(cipher_bytes, rsa_priv_key_seq)}
  catch
    kind, error ->
      ExPublicKey.normalize_error(kind, error)
  end

  def decrypt_private(cipher_text, private_key, opts \\ []) do
    url_safe = Keyword.get(opts, :url_safe, true)

    with {:ok, decoded_cipher_text} <- decode(cipher_text, url_safe),
         {:ok, [cipher_bytes, rsa_priv_key_seq]} <-
           decrypt_private_0(decoded_cipher_text, private_key),
         do: decrypt_private_1([cipher_bytes, rsa_priv_key_seq])
  end

  defp decrypt_public_0(cipher_bytes, public_key) do
    case ExPublicKey.RSAPublicKey.as_sequence(public_key) do
      {:ok, rsa_pub_key_seq} -> {:ok, [cipher_bytes, rsa_pub_key_seq]}
      {:error, reason} -> {:error, reason}
    end
  end

  defp decrypt_public_1([cipher_bytes, rsa_pub_key_seq]) do
    {:ok, :public_key.decrypt_public(cipher_bytes, rsa_pub_key_seq)}
  catch
    kind, error ->
      ExPublicKey.normalize_error(kind, error)
  end

  def decrypt_public(cipher_text, public_key, opts \\ []) do
    url_safe = Keyword.get(opts, :url_safe, true)

    with {:ok, decoded_cipher_text} <- decode(cipher_text, url_safe),
         {:ok, [cipher_bytes, rsa_pub_key_seq]} <-
           decrypt_public_0(decoded_cipher_text, public_key),
         do: decrypt_public_1([cipher_bytes, rsa_pub_key_seq])
  end

  def generate_key, do: generate_key(:rsa, 2048, 65537)
  def generate_key(bits), do: generate_key(:rsa, bits, 65537)
  def generate_key(bits, public_exp), do: generate_key(:rsa, bits, public_exp)

  def generate_key(:rsa, bits, public_exp),
    do: generate_key(:rsa, bits, public_exp, otp_has_rsa_gen_support())

  @doc """
  Generate a new key.
  Note: To ensure Backwards compatibility when generating rsa keys on OTP < 20, we fall back to openssl via System.cmd.

  ## Example

      {:ok, rsa_priv_key} = ExPublicKey.generate_key(:rsa, 2048)

  """
  def generate_key(type, bits, public_exp) do
    {:ok, :public_key.generate_key({type, bits, public_exp})}
  catch
    kind, error ->
      ExPublicKey.normalize_error(kind, error)
  end

  def generate_key(:rsa, bits, _public_exp, false) do
    # Fallback support for OTP 18 & 19.
    generate_rsa_openssl_fallback(bits)
  end

  def generate_key(:rsa, bits, public_exp, true) do
    new_rsa_key =
      :public_key.generate_key({:rsa, bits, public_exp})
      |> ExPublicKey.RSAPrivateKey.from_sequence()

    {:ok, new_rsa_key}
  end

  @doc """
  Extract the public part of a private string and return the results as a ExPublicKey.RSAPublicKey struct.

  ## Example

      {:ok, rsa_pub_key} = ExPublicKey.public_key_from_private_key(rsa_priv_key)

  """
  def public_key_from_private_key(private_key = %ExPublicKey.RSAPrivateKey{}) do
    {:ok,
     ExPublicKey.RSAPublicKey.from_sequence(
       {:RSAPublicKey, private_key.public_modulus, private_key.public_exponent}
     )}
  end

  @doc """
  Encode a key into a PEM string.
  To decode, use `ExPublicKey.loads/1`

  ## Example
      {:ok, pem_string} = ExPublicKey.pem_encode(key)

  """
  def pem_encode(key = %ExPublicKey.RSAPrivateKey{}) do
    with {:ok, key_sequence} <- ExPublicKey.RSAPrivateKey.as_sequence(key),
         do: pem_entry_encode(key_sequence, :RSAPrivateKey)
  end

  def pem_encode(key = %ExPublicKey.RSAPublicKey{}) do
    with {:ok, key_sequence} <- ExPublicKey.RSAPublicKey.as_sequence(key),
         do: pem_entry_encode(key_sequence, :RSAPublicKey)
  end

  # Helpers
  defp pem_entry_encode(key, type) do
    pem_entry = :public_key.pem_entry_encode(type, key)
    {:ok, :public_key.pem_encode([pem_entry])}
  catch
    kind, error ->
      ExPublicKey.normalize_error(kind, error)
  end

  defp decode(encoded_payload, _url_safe = true) do
    Base.url_decode64(encoded_payload)
  end

  defp decode(encoded_payload, _url_safe = false) do
    Base.decode64(encoded_payload)
  end

  defp encode(payload_bytes, _url_safe = true) do
    Base.url_encode64(payload_bytes)
  end

  defp encode(payload_bytes, _url_safe = false) do
    Base.encode64(payload_bytes)
  end

  # Erlang public_key v1.4.1 corresponds to Erlang/OTP 20.0
  defp otp_has_rsa_gen_support() do
    Application.spec(:public_key, :vsn)
    |> Kernel.to_string()
    |> String.split(".")
    |> Enum.map(fn i ->
      {i_int, _} = Integer.parse(i)
      i_int
    end)
    |> otp_has_rsa_gen_support_z()
  end

  defp otp_has_rsa_gen_support_z(version_int_list) do
    version_int_list >= @otp_20_public_key_version
  end

  defp generate_rsa_openssl_fallback(bits) do
    with {pem_entry, 0} <- System.cmd("openssl", ["genrsa", to_string(bits)]) do
      loads(pem_entry)
    else
      {result, ret_code} ->
        {:error, "result=#{result} ret_code=#{ret_code}"}
    end
  end
end

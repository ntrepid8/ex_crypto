defmodule ExPublicKey do

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
        {kind, x, System.stacktrace}
    end
  end

  def load(file_path, passphrase \\ nil) do
    case File.read(file_path) do
      {:ok, key_string} ->
        if passphrase do
          ExPublicKey.loads(key_string, passphrase)
        else
          ExPublicKey.loads(key_string)
        end
      {:error, reason} ->
        {:error, reason}
    end
  end

  def load!(file_path) do
    case load(file_path) do
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

  def loads(pem_string) do
    pem_entries = :public_key.pem_decode(pem_string)
    with {:ok, pem_entry} <- validate_pem_length(pem_entries),
         {:ok, rsa_key} <- load_pem_entry(pem_entry),
    do: sort_key_tup(rsa_key)
  end

  def loads(pem_string, passphrase) do
    pem_entries = :public_key.pem_decode(pem_string)
    with {:ok, pem_entry} <- validate_pem_length(pem_entries),
         {:ok, rsa_key} <- load_pem_entry(pem_entry, passphrase),
    do: sort_key_tup(rsa_key)
  end

  def loads!(pem_string) do
    case loads(pem_string) do
      {:ok, key} ->
        key
      {:error, reason} ->
        raise ExCrypto.Error, reason: reason
    end
  end

  defp load_pem_entry(pem_entry, passphrase \\ nil) do
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
        {:error, "invalid argument, expected one of[ExPublicKey.RSAPublicKey, ExPublicKey.RSAPrivateKey], found: #{x}"}
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
         {:ok, [cipher_bytes, rsa_priv_key_seq]} <- decrypt_private_0(decoded_cipher_text, private_key),
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
         {:ok, [cipher_bytes, rsa_pub_key_seq]} <- decrypt_public_0(decoded_cipher_text, public_key),
      do: decrypt_public_1([cipher_bytes, rsa_pub_key_seq])
  end

  # Helpers
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

end

defmodule ExPublicKey do
  use Pipe

  def normalize_error(kind, error) do
    case Exception.normalize(kind, error) do
      %{message: message} ->
        {:error, message}
      x ->
        {kind, x, System.stacktrace}
    end
  end

  def load(file_path) do
    case File.read(file_path) do
      {:ok, key_string} ->
        ExPublicKey.loads(key_string)
      {:error, reason} ->
        {:error, reason}
      _ ->
        {:error, "invalid argument"}
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
    pipe_matching x, {:ok, x},
      validate_pem_length(pem_entries)
      |> load_pem_entry
      |> sort_key_tup
  end

  def loads!(pem_string) do
    case loads(pem_string) do
      {:ok, key} ->
        key
      {:error, reason} ->
        raise ExCrypto.Error, reason: reason
    end
  end

  defp load_pem_entry(pem_entry) do
    {:ok, :public_key.pem_entry_decode(pem_entry)}
  catch
    kind, error ->
      ExPublicKey.normalize_error(kind, error)
  end

  defp sort_key_tup(key_tup) do
    case elem(key_tup, 0) do
      :RSAPrivateKey ->
        {:ok, RSAPrivateKey.from_sequence(key_tup)}
      :RSAPublicKey ->
        {:ok, RSAPublicKey.from_sequence(key_tup)}
      x ->
        {:error, "invalid argument, expected one of[RSAPublicKey, RSAPrivateKey], found: #{x}"}
    end
  end

  defp sign_0(rsa_priv_key_seq, msg, sha) do
    {:ok, :public_key.sign(msg, sha, rsa_priv_key_seq)}
  catch
    kind, error ->
      ExPublicKey.normalize_error(kind, error)
  end

  def sign(msg, sha, private_key) do
    pipe_matching x, {:ok, x},
      RSAPrivateKey.as_sequence(private_key)
      |> sign_0(msg, sha)
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
    pipe_matching x, {:ok, x},
      RSAPublicKey.as_sequence(public_key)
      |> verify_0(msg, sha, signature)
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

  defp url_encode64(bytes_to_encode) do
    {:ok, Base.url_encode64(bytes_to_encode)}
  end

  def encrypt_private(clear_text, private_key) do
    pipe_matching x, {:ok, x},
      RSAPrivateKey.as_sequence(private_key)
      |> encrypt_private_0(clear_text)
      |> url_encode64
  end

  defp encrypt_public_0(rsa_pub_key_seq, clear_text) do
    {:ok, :public_key.encrypt_public(clear_text, rsa_pub_key_seq)}
  catch
    kind, error ->
      ExPublicKey.normalize_error(kind, error)
  end

  def encrypt_public(clear_text, public_key) do
    pipe_matching x, {:ok, x},
      RSAPublicKey.as_sequence(public_key)
      |> encrypt_public_0(clear_text)
      |> url_encode64
  end

  defp decrypt_private_0(cipher_bytes, private_key) do
    case RSAPrivateKey.as_sequence(private_key) do
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

  def decrypt_private(cipher_text, private_key) do
    pipe_matching x, {:ok, x},
      Base.url_decode64(cipher_text)
      |> decrypt_private_0(private_key)
      |> decrypt_private_1
  end

  defp decrypt_public_0(cipher_bytes, public_key) do
    case RSAPublicKey.as_sequence(public_key) do
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

  def decrypt_public(cipher_text, public_key) do
    pipe_matching x, {:ok, x},
      Base.url_decode64(cipher_text)
      |> decrypt_public_0(public_key)
      |> decrypt_public_1
  end
end

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
  
  def loads(pem_string) do
    pem_entries = :public_key.pem_decode(pem_string)
    case length(pem_entries) do
      0 ->
        {:error, "invalid argument"}
      x when x > 1 ->
        {:error, "found multiple PEM entries, expected only 1"}
      x when x == 1 ->
        case load_pem_entry(Enum.at(pem_entries, 0)) do
          {:error, reason} ->
            {:error, reason}
          {:ok, key} ->
            {:ok, key}
          _ ->
            {:error, "something unexpected happened"}
        end
    end
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
    key_tup = :public_key.pem_entry_decode(pem_entry)
    case elem(key_tup, 0) do
      :RSAPrivateKey ->
        {:ok, RSAPrivateKey.from_sequence(key_tup)}
      :RSAPublicKey ->
        {:ok, RSAPublicKey.from_sequence(key_tup)}
      x ->
        {:error, "invalid argument, expected one of[RSAPublicKey, RSAPrivateKey], found: #{x}"}
    end
  end

  defp sign_0()

  def sign(msg, sha, private_key) do
    case RSAPrivateKey.as_sequence(private_key) do
      {:ok, rsa_priv_key_seq} ->
        signature = try do
          :public_key.sign(msg, sha, rsa_priv_key_seq)
        catch
          kind, error ->
            ExPublicKey.normalize_error(kind, error)
        end
        {:ok, signature}
      {:error, reason} ->
        {:error, reason}
    end
  end

  def sign(msg, private_key) do
    ExPublicKey.sign(msg, :sha256, private_key)
  end

  def verify(msg, sha, signature, public_key) do
    {:ok, rsa_pub_key_seq} = RSAPublicKey.as_sequence(public_key)
    signature_valid = try do
      :public_key.verify(msg, sha, signature, rsa_pub_key_seq)
    catch
      kind, error ->
        ExPublicKey.normalize_error(kind, error)
    end
    {:ok, signature_valid}
  end

  def verify(msg, signature, public_key) do
    ExPublicKey.verify(msg, :sha256, signature, public_key)
  end

  def encrypt_private(clear_text, private_key) do
    {:ok, rsa_priv_key_seq} = RSAPrivateKey.as_sequence(private_key)
    cipher_bytes = try do
      :public_key.encrypt_private(clear_text, rsa_priv_key_seq)
    catch
      kind, error ->
        ExPublicKey.normalize_error(kind, error)
    end
    Base.url_encode64(cipher_bytes)
  end

  def encrypt_public(clear_text, public_key) do
    {:ok, rsa_pub_key_seq} = RSAPublicKey.as_sequence(public_key)
    cipher_bytes = try do
      :public_key.encrypt_public(clear_text, rsa_pub_key_seq)
    catch
      kind, error ->
        ExPublicKey.normalize_error(kind, error)
    end
    {:ok, Base.url_encode64(cipher_bytes)}
  end

  def decrypt_private(cipher_text, private_key) do
    {:ok, cipher_bytes} = Base.url_decode64(cipher_text)
    {:ok, rsa_priv_key_seq} = RSAPrivateKey.as_sequence(private_key)
    clear_text = try do
      :public_key.decrypt_private(cipher_bytes, rsa_priv_key_seq)
    catch
      kind, error ->
        ExPublicKey.normalize_error(kind, error)
    end
    {:ok, clear_text}
  end

  def decrypt_public(cipher_text, public_key) do
    {:ok, cipher_bytes} = Base.url_decode64(cipher_text)
    {:ok, rsa_pub_key_seq} = RSAPublicKey.as_sequence(public_key)
    clear_text = try do
      :public_key.decrypt_public(cipher_bytes, rsa_pub_key_seq)
    catch
      kind, error ->
        ExPublicKey.normalize_error(kind, error)
    end
    {:ok, clear_text}
  end
end

defmodule ExPublicKey do

  def load(file_path) do
    case File.read(file_path) do
      {:ok, key_string} ->
        {:ok, ExPublicKey.loads(key_string)}
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

  def sign(msg, sha, key) do
    :public_key.sign(msg, sha, key)
  end

  def sign(msg, key) do
    ExPublicKey.sign(msg, :sha256, key)
  end
end

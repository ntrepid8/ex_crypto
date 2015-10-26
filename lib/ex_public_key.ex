defmodule ExPublicKey do

  def load(file_path) do
    case File.read(file_path) do
      {:ok, key_string} ->
        ExPublicKey.loads(key_string)
      {:error, reason} ->
        raise File.error, reason
      _ ->
        raise ArgumentError, message: "invalid argument"
    end
  end
  
  def loads(pem_string) do
    pem_entries = :public_key.pem_decode(pem_string)
    case length(pem_entries) do
      0 ->
        raise ArgumentError, message: "invalid argument"
      x when x > 1 ->
        raise ArgumentError, message: "found multiple PEM entries, expected only 1"
      x when x == 1 ->
        load_pem_entry(Enum.at(pem_entries, 0))
    end
  end

  defp load_pem_entry(pem_entry) do
    key_tup = :public_key.pem_entry_decode(pem_entry)
    case elem(key_tup, 0) do
      :RSAPrivateKey ->
        RSAPrivateKey.from_sequence(key_tup)
      :RSAPublicKey ->
        RSAPublicKey.from_sequence(key_tup)
      x ->
        raise ArgumentError, message: "invalid argument, expected one of[RSAPublicKey, RSAPrivateKey], found: #{x}"
    end
  end

  def sign(msg, sha, key) do
    :public_key.sign(msg, sha, key)
  end

  def sign(msg, key) do
    ExPublicKey.sign(msg, :sha256, key)
  end
end

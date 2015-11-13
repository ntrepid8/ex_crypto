defmodule ExCrypto.HMAC do

  def hmac(data, key) do
    hmac(data, key, type: :sha256)
  end

  def hmac!(data, key) do
    case hmac(data, key) do
      {:ok, data} -> data
      {:error, reason} -> raise reason
  end

  def hmac(data, key, [type: :sha256]) do
    {:ok, :crypto.hmac(:sha256, key, data)}
  end

  def verify_hmac(data, key, other_mac) do
    verify_hmac(data, key, other_mac, type: :sha256)
  end

  def verify_hmac(data, key, other_mac, [type: :sha256]) do
    case hmac(data, key, type: :sha256) do
      {:ok, my_mac} -> case my_mac === other_mac do
        true -> {:ok, true}
        false -> {:ok, false}
      end
      {:error, reason} -> {:error, reason}
    end
  end
  
end
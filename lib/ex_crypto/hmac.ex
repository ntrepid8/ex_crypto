defmodule ExCrypto.HMAC do
  def hmac(data, key) do
    hmac(data, key, type: :sha256)
  end

  def hmac!(data, key) do
    case hmac(data, key) do
      {:ok, data} -> data
      {:error, reason} -> raise reason
    end
  end

  def hmac(data, key, type: type = :sha256) do
    try do
      {:ok, crypto_mac(type, key, data)}
    rescue
      e in ArgumentError -> {:error, e}
    end
  end

  def verify_hmac(data, key, other_mac) do
    verify_hmac(data, key, other_mac, type: :sha256)
  end

  def verify_hmac(data, key, other_mac, type: :sha256) do
    case hmac(data, key, type: :sha256) do
      {:ok, my_mac} ->
        case my_mac === other_mac do
          true -> {:ok, true}
          false -> {:ok, false}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  # :crypto.mac added in otp 22.1, :crypto.hmac deprecated in 23 and removed in 24
  # http://erlang.org/doc/apps/crypto/new_api.html#the-new-api
  if System.otp_release() |> String.to_integer() >= 23 do
    defp crypto_mac(type, key, data) do
      :crypto.mac(:hmac, type, key, data)
    end
  else
    defp crypto_mac(type, key, data) do
      :crypto.hmac(type, key, data)
    end
  end
end

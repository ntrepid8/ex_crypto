defmodule ExCrypto.Hash do
  def sha256(data) do
    try do
      {:ok, :crypto.hash(:sha256, data)}
    rescue
      e in ArgumentError -> {:error, e}
    end
  end

  def sha256!(data) do
    case sha256(data) do
      {:ok, digest} -> digest
      {:error, reason} -> raise "sha256 error: #{inspect(reason)}"
    end
  end

  def sha512(data) do
    try do
      {:ok, :crypto.hash(:sha512, data)}
    rescue
      e in ArgumentError -> {:error, e}
    end
  end

  def sha512!(data) do
    case sha512(data) do
      {:ok, digest} -> digest
      {:error, reason} -> raise "sha512 error: #{inspect(reason)}"
    end
  end
end

defmodule ExCrypto.Hash do
  def sha256(data) do
    {:ok, :crypto.hash(:sha256, data)}
  end

  def sha256!(data) do
    case sha256(data) do
      {:ok, digest} -> digest
      {:error, reason} -> raise "sha256 error"
    end
  end

  def sha512(data) do
    {:ok, :crypto.hash(:sha512, data)}
  end

  def sha512!(data) do
    case sha512(data) do
      {:ok, digest} -> digest
      {:error, reason} -> raise "sha512 error"
    end
  end
end

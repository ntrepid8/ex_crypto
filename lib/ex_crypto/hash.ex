defmodule ExCrypto.Hash do
  def sha256(data) do
    {:ok, :crypto.hash(:sha256, data)}
  end

  def sha512(data) do
    {:ok, :crypto.hash(:sha512, data)}
  end
end

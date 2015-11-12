defmodule ExCryptoHashTest do
  use ExUnit.Case

  test "sha256" do
    {:ok, data} = ExCrypto.rand_bytes(128)
    e_sha256_digest = :crypto.hash(:sha256, data)

    {:ok, sha256_digest} = ExCrypto.Hash.sha256(data)
    assert(e_sha256_digest === sha256_digest)
  end

  test "sha512" do
    {:ok, data} = ExCrypto.rand_bytes(128)
    e_sha512_digest = :crypto.hash(:sha512, data)

    {:ok, sha512_digest} = ExCrypto.Hash.sha512(data)
    assert(e_sha512_digest === sha512_digest)
  end
end

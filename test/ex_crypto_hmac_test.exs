defmodule ExCryptoHMACTest do
  use ExUnit.Case

  setup do
    # Generate a key and data to work with
    {:ok, aes_128_key} = ExCrypto.generate_aes_key(:aes_128, :bytes)
    {:ok, data} = ExCrypto.rand_bytes(32)

    {:ok, aes_128_key: aes_128_key, data: data}
  end

  test "generate and verify HMAC", context do
    # Generate the MAC
    {:ok, mac} = ExCrypto.HMAC.hmac(context[:data], context[:aes_128_key])
    assert(mac !== nil)
    assert(is_binary(mac))

    # Check it matches the Erlang
    check_mac = :crypto.hmac(:sha256, context[:aes_128_key], context[:data])
    assert(check_mac === mac)

    # Check it does not match when a different key is used
    {:ok, other_aes_128_key} = ExCrypto.generate_aes_key(:aes_128, :bytes)
    {:ok, other_mac} = ExCrypto.HMAC.hmac(context[:data], other_aes_128_key)
    assert(mac !== other_mac)
  end

  test "hmac_verify with valid MAC", context do
    # Generate the MAC
    {:ok, mac} = ExCrypto.HMAC.hmac(context[:data], context[:aes_128_key])
    assert(mac !== nil)
    assert(is_binary(mac))

    {:ok, mac_is_valid} = ExCrypto.HMAC.verify_hmac(context[:data], context[:aes_128_key], mac)
    assert(mac_is_valid)
  end

  test "hmac_verify with invalid MAC", context do
    # Generate a different key
    {:ok, other_aes_128_key} = ExCrypto.generate_aes_key(:aes_128, :bytes)

    # Generate the MAC
    {:ok, invalid_mac} = ExCrypto.HMAC.hmac(context[:data], other_aes_128_key)
    assert(invalid_mac !== nil)
    assert(is_binary(invalid_mac))

    {:ok, mac_is_valid} =
      ExCrypto.HMAC.verify_hmac(context[:data], context[:aes_128_key], invalid_mac)

    assert(mac_is_valid === false)
  end
end

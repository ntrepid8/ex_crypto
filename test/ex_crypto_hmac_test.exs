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
    check_mac = crypto_mac(:sha256, context[:aes_128_key], context[:data])
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

  test "HMAC sanity test" do
    key = <<1::256>>
    expected = <<255, 242, 109, 110, 128, 183, 203, 185, 101, 218, 219, 200, 6, 30, 144, 10, 165, 252, 221, 4, 107, 207, 219, 113, 18, 133, 129, 128, 100, 176, 203, 228>>
    {:ok, ^expected} = ExCrypto.HMAC.hmac("Some data", key)
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

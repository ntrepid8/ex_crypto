defmodule ExCrypto.ExTokenTest do
  use ExUnit.Case
  require Logger

  test "Token.create/3 and Token.verify/4" do
    payload = %{"foo" => "bar", "spam" => "eggs"}
    encoded_payload = Poison.encode!(payload)
    {:ok, secret} = ExCrypto.generate_aes_key(:aes_256, :bytes)

    # create the token
    result = ExCrypto.Token.create(encoded_payload, secret)
    assert match?({:ok, _}, result)
    {:ok, token} = result

    # verify the token
    ttl = 15*60  # 15 minute TTL
    result = ExCrypto.Token.verify(token, secret, ttl)
    Logger.debug("result=#{inspect result}")
    assert assert match?({:ok, _}, result)
  end
end

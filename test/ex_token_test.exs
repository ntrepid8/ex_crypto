defmodule ExCrypto.ExTokenTest do
  use ExUnit.Case
  doctest ExCrypto.Token
  require Logger

  test "Token.create/3 and Token.verify/4 (basic)" do
    payload = %{"foo" => "bar", "spam" => "eggs"}
    encoded_payload = Jason.encode!(payload)
    {:ok, secret} = ExCrypto.generate_aes_key(:aes_256, :bytes)

    # create the token
    result = ExCrypto.Token.create(encoded_payload, secret)
    assert match?({:ok, _}, result)
    {:ok, token} = result

    # verify the token
    # 15 minute TTL
    ttl = 15 * 60
    result = ExCrypto.Token.verify(token, secret, ttl)
    assert assert match?({:ok, _}, result)
    {:ok, v_payload} = result
    assert v_payload == encoded_payload
  end

  test "Token.create/3 and Token.verify/4 (token too old)" do
    now_dt = :calendar.universal_time()
    now_seconds = :calendar.datetime_to_gregorian_seconds(now_dt)
    past_seconds = now_seconds - 30 * 60
    past_dt = :calendar.gregorian_seconds_to_datetime(past_seconds)

    payload = %{"foo" => "bar", "spam" => "eggs"}
    encoded_payload = Jason.encode!(payload)
    {:ok, secret} = ExCrypto.generate_aes_key(:aes_256, :bytes)

    # create the token (in the past)
    opts = [date_time: past_dt]
    result = ExCrypto.Token.create(encoded_payload, secret, opts)
    assert match?({:ok, _}, result)
    {:ok, token} = result

    # verify the token
    # 15 minute TTL
    ttl = 15 * 60
    result = ExCrypto.Token.verify(token, secret, ttl)
    assert match?({:error, _}, result)
  end

  test "Token.create/3 and Token.verify/4 (token in future)" do
    now_dt = :calendar.universal_time()
    now_seconds = :calendar.datetime_to_gregorian_seconds(now_dt)
    future_seconds = now_seconds + 30 * 60
    future_dt = :calendar.gregorian_seconds_to_datetime(future_seconds)

    payload = %{"foo" => "bar", "spam" => "eggs"}
    encoded_payload = Jason.encode!(payload)
    {:ok, secret} = ExCrypto.generate_aes_key(:aes_256, :bytes)

    # create the token (in the future)
    opts = [date_time: future_dt]
    result = ExCrypto.Token.create(encoded_payload, secret, opts)
    assert match?({:ok, _}, result)
    {:ok, token} = result

    # verify the token
    # 15 minute TTL
    ttl = 15 * 60
    result = ExCrypto.Token.verify(token, secret, ttl)
    assert match?({:error, _}, result)
  end

  test "Token.update/4 (basic)" do
    now_dt = :calendar.universal_time()
    now_seconds = :calendar.datetime_to_gregorian_seconds(now_dt)
    # 10 min
    past_seconds = now_seconds - 10 * 60
    past_dt = :calendar.gregorian_seconds_to_datetime(past_seconds)

    payload = %{"foo" => "bar", "spam" => "eggs"}
    encoded_payload = Jason.encode!(payload)
    {:ok, secret} = ExCrypto.generate_aes_key(:aes_256, :bytes)

    # create the token
    opts = [date_time: past_dt]
    result = ExCrypto.Token.create(encoded_payload, secret, opts)
    assert match?({:ok, _}, result)
    {:ok, token} = result

    # verify the token (pass with 15 min TTL)
    # 15 minute TTL
    ttl = 15 * 60
    result = ExCrypto.Token.verify(token, secret, ttl)
    assert match?({:ok, _}, result)
    {:ok, v_payload} = result
    assert v_payload == encoded_payload

    # verify the token (fail with 5 min TTL)
    # 5 minute TTL
    ttl = 5 * 60
    result = ExCrypto.Token.verify(token, secret, ttl)
    assert match?({:error, _}, result)

    # update the token
    # 15 minute TTL
    ttl = 15 * 60
    result = ExCrypto.Token.update(token, secret, ttl)
    assert match?({:ok, {_, _}}, result)
    {:ok, {update_token, update_payload}} = result
    assert update_payload == encoded_payload

    # verify the updated token (pass with 5 min TTL)
    # 5 minute TTL
    ttl = 5 * 60
    result = ExCrypto.Token.verify(update_token, secret, ttl)
    assert match?({:ok, _}, result)
    {:ok, v_payload} = result
    assert v_payload == encoded_payload
  end
end

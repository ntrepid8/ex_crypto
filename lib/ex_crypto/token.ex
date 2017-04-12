defmodule ExCrypto.Token do
  @moduledoc """
  The ExCrypto Token helper.

  Generate signed tokens that can expire after a certain amount of time. These
  tokens are useful when you have a secret that is not shared with any other
  systems.
  """
  alias ExCrypto.HMAC
  require Logger

  # type specs
  @type option :: {:divider, String.t} |
                  {:date_time, {{integer, integer, integer}, {integer, integer, integer}}}
  @type options :: [option]
  @type token :: binary

  @epoch :calendar.datetime_to_gregorian_seconds({{1970, 1, 1}, {0, 0, 0}})
  @fifteen_min_in_seconds 15*60

  @doc """
  Generate a signed token that carries of timestamp of when it was signed.
  """
  @spec create(binary, binary, options) :: {:ok, token} | {:error, any}
  def create(payload, secret, opts \\ []) do
    now_dt = Keyword.get(opts, :date_time, :calendar.universal_time())
    now_ts = dt_to_ts(now_dt)
    case HMAC.hmac(["#{now_ts}", payload], secret) do
      {:ok, mac} ->
          encoded_token = encode_token([payload, now_ts, mac])
        {:ok, encoded_token}
      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Like `create/3` but raises an exception on error.
  """
  @spec create!(binary, binary, options) :: binary | no_return
  def create!(payload, secret, opts \\ []) do
    case create(payload, secret, opts) do
      {:ok, token} -> token
      {:error, reason} -> raise reason
    end
  end

  @doc """
  Verify a token. Ensure the signature is no older than the `ttl`.
  """
  @spec verify(token, binary, integer, options) :: {:ok, token} | {:error, any}
  def verify(token, secret, ttl, opts \\ []) do
    now_dt = Keyword.get(opts, :date_time, :calendar.universal_time())
    now_ts = dt_to_ts(now_dt)

    with {:ok, [payload, sig_ts_raw, mac]} <- decode_token(token),
         {:ok, sig_ts} <- validate_sig_ts(sig_ts_raw, ttl, now_ts)
    do
      case HMAC.verify_hmac(["#{sig_ts}", payload], secret, mac) do
        {:ok, true} ->
          {:ok, token}
        _ ->
          Logger.debug("HMAC failed to validate")
          {:error, :invalid_token}
      end
    end
  end

  @doc """
  Like `verify/4` but raises an exception on error.
  """
  @spec verify!(binary, binary, integer, options) :: binary | no_return
  def verify!(token, secret, ttl, opts \\ []) do
    case verify(token, secret, ttl, opts) do
      {:ok, token} -> token
      {:error, reason} -> raise reason
    end
  end

  defp encode_token([payload, sig_ts, bin_mac]) do
    <<bin_mac::bits-size(256), sig_ts::integer-size(64), payload::binary>>
    |> Base.url_encode64()
  end

  defp decode_token(encoded_token) do
    case Base.url_decode64(encoded_token) do
      {:ok, bin_token} ->
        decode_token_0(bin_token)
      _ ->
        Logger.debug("token was not encoded with valid URL safe base64 encoding")
        {:error, :invalid_token}
    end
  end

  defp decode_token_0(<<bin_mac::bits-size(256), sig_ts::integer-size(64), payload::binary>>) do
    {:ok, [payload, sig_ts, bin_mac]}
  end
  defp decode_token_0(_invalid_token) do
    Logger.debug("token does not have the correct binary structure")
    {:error, :invalid_token}
  end

  defp validate_sig_ts(sig_ts, ttl, now_ts) do
    cond do
      # too old
      (sig_ts + ttl) < now_ts ->
        Logger.debug("timestamp #{sig_ts} with ttl #{ttl} is too old")
        {:error, :invalid_token}

      # in future
      (now_ts + @fifteen_min_in_seconds) < sig_ts ->
        Logger.debug("timestamp #{sig_ts} with ttl #{ttl} is in the future")
        {:error, :invalid_token}

      # valid
      ## signature timestamp plus TTL is in the future (not expired)
      (sig_ts + ttl) > now_ts
      ## signature timestamp alone is not more than 15 minutes in the future (sanity)
      and sig_ts < (now_ts + @fifteen_min_in_seconds) ->
        {:ok, sig_ts}

      # signature timestamp is outside the valid range
      true ->
        Logger.debug("timestamp #{sig_ts} with ttl #{ttl} is outside the valid range")
        {:error, :invalid_token}
    end
  end

  # defp ts_to_dt(timestamp) do
  #   :calendar.gregorian_seconds_to_datetime(timestamp + @epoch)
  # end

  def dt_to_ts(date_time) do
    :calendar.datetime_to_gregorian_seconds(date_time) - @epoch
  end
end

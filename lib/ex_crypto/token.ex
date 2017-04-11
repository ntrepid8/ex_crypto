defmodule ExCrypto.Token do
  @moduledoc """
  The ExCrypto Token helper.

  Generate signed tokens that can expire after a certain amount of time. These
  tokens are useful when you have a secret that is not shared with any other
  systems.
  """
  alias ExCrypto.HMAC

  @type option :: {:divider, String.t} |
                  {:date_time, {{integer, integer, integer}, {integer, integer, integer}}}
  @type options :: [option]

  @epoch :calendar.datetime_to_gregorian_seconds({{1970, 1, 1}, {0, 0, 0}})
  @fifteen_min_in_seconds 15*60

  @doc """
  Generate a signed token that carries of timestamp of when it was signed.
  """
  @spec create(binary, binary, options) :: {:ok, binary} | {:error, any}
  def create(payload, secret, opts \\ []) do
    divider = Keyword.get(opts, :divider, "|")
    now_dt = Keyword.get(opts, :date_time, :calendar.universal_time())
    now_ts = dt_to_ts(now_dt)
    case HMAC.hmac(["#{now_ts}", payload], secret) do
      {:ok, mac} ->
          encoded_token = encode_token([payload, "#{now_ts}", mac], divider)
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
  @spec verify(binary, binary, integer, options) :: {:ok, binary} | {:error, any}
  def verify(token, secret, ttl, opts \\ []) do
    divider = Keyword.get(opts, :divider, "|")
    now_dt = Keyword.get(opts, :date_time, :calendar.universal_time())
    now_ts = dt_to_ts(now_dt)

    with {:ok, [payload, sig_ts_raw, mac]} <- decode_token_0(token, divider),
         {:ok, sig_ts} <- validate_sig_ts(sig_ts_raw, ttl, now_ts)
    do
      case HMAC.verify_hmac(["#{sig_ts}", payload], secret, mac) do
        {:ok, true} -> {:ok, token}
        _           -> {:error, :invalid_token}
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

  defp encode_token([payload, sig_ts, bin_mac], divider) do
    encoded_payload_and_timestamp =
      [payload, "#{sig_ts}"]
      |> Enum.join(divider)
      |> Base.encode64(padding: false)

    [encoded_payload_and_timestamp, Base.encode64(bin_mac, padding: false)]
    |> Enum.join(divider)
  end

  defp decode_token_0(token, divider) do
    case String.split(token, divider) do
      [encoded_payload_and_timestamp, encoded_mac] ->
        decode_token_1([encoded_payload_and_timestamp, encoded_mac], divider)
      _ ->
        {:error, :invalid_token}
    end
  end

  defp decode_token_1([encoded_payload_and_timestamp, encoded_mac], divider) do
    case Base.decode64(encoded_payload_and_timestamp, padding: false) do
      {:ok, decoded_payload_and_timestamp} ->
        decode_token_2([decoded_payload_and_timestamp, encoded_mac], divider)
      _ ->
        {:error, :invalid_token}
    end
  end

  defp decode_token_2([decoded_payload_and_timestamp, encoded_mac], divider) do
    case String.split(decoded_payload_and_timestamp, divider) do
      [payload, sig_ts_str] ->
        decode_token_3([payload, sig_ts_str, encoded_mac], divider)
      _ ->
        {:error, :invalid_token}
    end
  end

  defp decode_token_3([payload, sig_ts_str, encoded_mac], divider) do
    case Base.decode64(encoded_mac, padding: false) do
      {:ok, bin_mac} ->
        {:ok, [payload, sig_ts_str, bin_mac]}
      _ ->
        {:error, :invalid_token}
    end
  end

  defp split_token(token, divider) do
    case String.split(token, divider) do
      [payload, sig_ts, mac_str] ->
        case Base.decode64(mac_str, padding: false) do
          {:ok, mac_bin} -> {:ok, [payload, sig_ts, mac_bin]}
          :error         -> {:error, :invalid_token}
        end

      _other ->
        {:error, :invalid_token}
    end
  end

  defp validate_sig_ts(sig_ts_raw, ttl, now_ts) do
    case Integer.parse(sig_ts_raw) do
      :error ->
        {:error, :invalid_token}
      {sig_ts, _} ->
        cond do
          # signature timestamp plus TTL is in the future (not expired)
          (sig_ts + ttl) > now_ts
          # signature timestamp alone is not more than 15 minutes in the future (sanity)
          and sig_ts < (now_ts + @fifteen_min_in_seconds) ->
            {:ok, sig_ts}

          # signature timestamp is outside the valid range
          true ->
            {:error, :invalid_token}
        end
    end
  end

  # defp ts_to_dt(timestamp) do
  #   :calendar.gregorian_seconds_to_datetime(timestamp + @epoch)
  # end

  def dt_to_ts(date_time) do
    :calendar.datetime_to_gregorian_seconds(date_time) - @epoch
  end
end

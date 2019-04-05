defmodule ExCrypto.Token do
  @moduledoc """
  Use `ExCrypto.Token` to create unforgeable HMAC tokens that expire after a TTL.

  Tokens created with this module have the following properties:

  - unforgeable
  - expire after a given TTL
  - may contain useful information in the payload (e.g. user_id or permissions)
  - safe to use in HTTP headers or URLs (encoded with `Base.url_encode64/1`)

  ## Basic usage

  Often it's convenient to include a JSON Object as the payload. That way the data in the payload
  is available after the token is verified like this:

      iex> payload = %{"user_id" => 12345}
      iex> encoded_payload = Jason.encode!(payload)
      iex> {:ok, secret} = ExCrypto.generate_aes_key(:aes_256, :bytes)
      iex> {:ok, token} = ExCrypto.Token.create(encoded_payload, secret)
      iex> ttl = (15 * 60)  # 15 minute TTL (in seconds)
      iex> {:ok, verified_payload} = ExCrypto.Token.verify(token, secret, ttl)
      iex> decoded_verified_payload = Jason.decode!(verified_payload)
      iex> assert(decoded_verified_payload == payload)
      iex> Map.get(decoded_verified_payload, "user_id")
      12345

  ### Notes

  - the payload is not encrypted, only base64 encoded, **do not include secrets in the payload**
  - do not create a new secret each time, it must be stored and kept *secret*
  - do not include the secret in the payload
  - store the secret in the config for your app if using one global secret
  - store the secret on a given record (e.g. user record) if using a unique secret for each user

  """
  alias ExCrypto.HMAC
  require Logger

  # type specs
  @type option ::
          {:divider, String.t()}
          | {:date_time, {{integer, integer, integer}, {integer, integer, integer}}}
  @type options :: [option]
  @type token :: binary
  @type payload :: binary

  @epoch :calendar.datetime_to_gregorian_seconds({{1970, 1, 1}, {0, 0, 0}})
  @fifteen_min_in_seconds 15 * 60

  @doc """
  Generate a signed token that carries of timestamp of when it was signed.

  #### Examples

      iex> payload = "my binary payload"
      iex> {:ok, secret} = ExCrypto.generate_aes_key(:aes_256, :bytes)
      iex> {:ok, token} = ExCrypto.Token.create(payload, secret)
      iex> ExCrypto.Token.is_token?(token)
      true

  """
  @spec create(payload, binary, options) :: {:ok, token} | {:error, any}
  def create(payload, secret, opts \\ []) do
    sig_dt = Keyword.get(opts, :date_time, :calendar.universal_time())
    sig_ts = dt_to_ts(sig_dt)
    {:ok, iv} = ExCrypto.rand_bytes(16)

    case HMAC.hmac([iv, "#{sig_ts}", payload], secret) do
      {:ok, mac} ->
        encoded_token = encode_token([iv, payload, sig_ts, mac])
        {:ok, encoded_token}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Like `create/3` but raises an exception on error.
  """
  @spec create!(payload, binary, options) :: binary | no_return
  def create!(payload, secret, opts \\ []) do
    case create(payload, secret, opts) do
      {:ok, token} -> token
      {:error, reason} -> raise reason
    end
  end

  @doc """
  Verify a token. Ensure the signature is no older than the `ttl`.

  #### Examples

      iex> payload = "my binary payload"
      iex> {:ok, secret} = ExCrypto.generate_aes_key(:aes_256, :bytes)
      iex> {:ok, token} = ExCrypto.Token.create(payload, secret)
      iex> ExCrypto.Token.is_token?(token)
      true
      iex> ttl = (15 * 60)  # 15 minute TTL (in seconds)
      iex> {:ok, verified_payload} = ExCrypto.Token.verify(token, secret, ttl)
      iex> verified_payload == payload
      true

  """
  @spec verify(token, binary, integer, options) :: {:ok, payload} | {:error, any}
  def verify(token, secret, ttl, opts \\ []) do
    sig_dt_challenge = Keyword.get(opts, :date_time, :calendar.universal_time())
    sig_ts_challenge = dt_to_ts(sig_dt_challenge)

    with {:ok, [iv, payload, sig_ts_raw, mac]} <- decode_token(token),
         {:ok, sig_ts} <- validate_sig_ts(sig_ts_raw, ttl, sig_ts_challenge) do
      case HMAC.verify_hmac([iv, "#{sig_ts}", payload], secret, mac) do
        {:ok, true} ->
          {:ok, payload}

        _ ->
          Logger.debug("HMAC failed to validate")
          {:error, :invalid_token}
      end
    end
  end

  @doc """
  Like `verify/4` but raises an exception on error.
  """
  @spec verify!(token, binary, integer, options) :: binary | no_return
  def verify!(token, secret, ttl, opts \\ []) do
    case verify(token, secret, ttl, opts) do
      {:ok, token} -> token
      {:error, reason} -> raise reason
    end
  end

  @doc """
  Update the signature on an existing token.

  This is useful if you want to have a token that expires quickly, but only
  if it is not being used.

  For example, if you use these tokens in a cookie
  for authentication in a web app, you can update the token each time the user
  makes a request, and send the updated cookie in the response.

  This way a user can be logged out after N minutes of inactivity without
  requiring the user to supply credentials every N minutes.

  This is also useful if the payload is expensive to create in the first place.

  Another important benefit is that since the token is rotated with each request
  stealing a token becomes much less valuable. It's not impossible,
  but because the token changes with each request old tokens are only good until
  their TTL expires.

  #### Examples

      iex> payload = "my binary payload"
      iex> {:ok, secret} = ExCrypto.generate_aes_key(:aes_256, :bytes)
      iex> {:ok, token} = ExCrypto.Token.create(payload, secret)
      iex> ExCrypto.Token.is_token?(token)
      true
      iex> ttl = (15 * 60)  # 15 minute TTL (in seconds)
      iex> {:ok, {update_token, update_payload}} = ExCrypto.Token.update(token, secret, ttl)
      iex> update_payload == payload
      true
      iex> {:ok, verified_payload} = ExCrypto.Token.verify(update_token, secret, ttl)
      iex> verified_payload == payload
      true

  """
  def update(token, secret, ttl, opts \\ []) do
    # first verify the token to ensure it's good to start with
    with {:ok, payload} <- verify(token, secret, ttl, opts),
         {:ok, update_token} <- create(payload, secret, opts),
         do: {:ok, {update_token, payload}}
  end

  @doc """
  Check if a given binary has the correct structure to be a token.

  This does not mean it is a valid token, only that it has all the parts of a token.

  #### Examples

      iex> payload = "my binary payload"
      iex> {:ok, secret} = ExCrypto.generate_aes_key(:aes_256, :bytes)
      iex> {:ok, token} = ExCrypto.Token.create(payload, secret)
      iex> ExCrypto.Token.is_token?(token)
      true

  """
  @spec is_token?(binary) :: true | false
  def is_token?(token) do
    case token do
      <<_mac::bits-size(256), _iv::bits-size(128), _sig_ts::integer-size(64), _payload::binary>> ->
        true

      _other ->
        false
    end
  end

  # Helpers

  defp encode_token([iv, payload, sig_ts, mac]) do
    <<mac::bits-size(256), iv::bits-size(128), sig_ts::integer-size(64), payload::binary>>
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

  defp decode_token_0(
         <<mac::bits-size(256), iv::bits-size(128), sig_ts::integer-size(64), payload::binary>>
       ) do
    {:ok, [iv, payload, sig_ts, mac]}
  end

  defp decode_token_0(_invalid_token) do
    Logger.debug("token does not have the correct binary structure")
    {:error, :invalid_token}
  end

  defp validate_sig_ts(sig_ts, ttl, now_ts) do
    cond do
      # too old
      sig_ts + ttl < now_ts ->
        Logger.debug("timestamp #{sig_ts} with ttl #{ttl} is too old")
        {:error, :invalid_token}

      # in future
      now_ts + @fifteen_min_in_seconds < sig_ts ->
        Logger.debug("timestamp #{sig_ts} with ttl #{ttl} is in the future")
        {:error, :invalid_token}

      # valid
      ## signature timestamp plus TTL is in the future (not expired)
      ## signature timestamp alone is not more than 15 minutes in the future (sanity)
      sig_ts + ttl > now_ts and sig_ts < now_ts + @fifteen_min_in_seconds ->
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

  defp dt_to_ts(date_time) do
    :calendar.datetime_to_gregorian_seconds(date_time) - @epoch
  end
end

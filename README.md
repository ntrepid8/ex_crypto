# ExCrypto

The goal of `ExCrypto` and `ExPublicKey` is to expose a subset of the functionality from the Erlang modules `crypto` and `public_key` so that writing secure Elixir applications is a little bit easier without being overwhelming. In many functions some sane defaults are provided to decrease the complexity of implementing those functions in your own code.

Get from hex.pm: <https://hex.pm/packages/ex_crypto>

Checkout the docs at: <https://hexdocs.pm/ex_crypto/readme.html>

## Build Status

[![Build Status](https://travis-ci.org/ntrepid8/ex_crypto.svg?branch=master)](https://travis-ci.org/ntrepid8/ex_crypto)

## Using ExPublicKey

The `ExPublicKey` module provides functions for working with RSA public/private key operations. There are a couple common uses for public-key cryptography:

- [Authenticate a message](#authenticate-a-message)
- [Transmit a shared secret](#transmit-a-shared-secret) (session key)

### Authenticate a message

The goal of `ExPublicKey.sign` and `ExPublicKey.verify` is that the recipient of a message can identify the sender. This can be accomplished as follows:

*Note: assume the message is a JSON payload.*

- Sender
  - serialize the JSON to a string
  - hash, time-stamp, and sign with your private-key
- Receiver
  - ensure the time-stamp is within the current window
  - verify the signature with the sender's public-key

Here are the steps in order:

```elixir
# load the RSA keys from a file on disk
rsa_priv_key = ExPublicKey.load!("/path/to/private_key.pem")
rsa_pub_key = ExPublicKey.load!("/path/to/public_key.pem")

# create the message JSON
msg = %{"name_first"=>"Chuck","name_last"=>"Norris"}

# serialize the JSON
msg_serialized = Poison.encode!(msg)

# generate time-stamp
ts = DateTime.utc_now |> DateTime.to_unix

# add a time-stamp
ts_msg_serialized = "#{ts}|#{msg_serialized}"

# generate a secure hash using SHA256 and sign the message with the private key
{:ok, signature} = ExPublicKey.sign(ts_msg_serialized, rsa_priv_key)

# combine payload
payload = "#{ts}|#{msg_serialized}|#{Base.url_encode64 signature}"
IO.puts payload

# pretend transmit the message...
# pretend receive the message...

# break up the payload
parts = String.split(payload, "|")
recv_ts = Enum.fetch!(parts, 0)
recv_msg_serialized = Enum.fetch!(parts, 1)
{:ok, recv_sig} = Enum.fetch!(parts, 2) |> Base.url_decode64

# pretend ensure the time-stamp is not too old (or from the future)...
# it should probably no more than 5 minutes old, and no more than 15 minutes in the future

# verify the signature
{:ok, sig_valid} = ExPublicKey.verify("#{recv_ts}|#{recv_msg_serialized}", recv_sig, rsa_pub_key)
assert(sig_valid)

# un-serialize the JSON
recv_msg_unserialized = Poison.Parser.parse!(recv_msg_serialized)
assert(msg == recv_msg_unserialized)
```
*Note: this example is similar to the test "sign and verify a JSON payload" in `test/ex_public_key_test.exs`.*

### Transmit a shared secret

*(in progress)*

### Load the keys from PEM format files

First load the public/private RSA keys from disk:

```elixir
iex(1)> {:ok, rsa_private_key} = ExPublicKey.load("/tmp/test_rsa_private_key.pem")
{:ok, %ExPublicKey.RSAPrivateKey{...}}

iex(2)> {:ok, rsa_public_key} = ExPublicKey.load("/tmp/test_rsa_public_key.pem")
{:ok, %ExPublicKey.RSAPublicKey{...}}
```

### Sign with RSA private key

To create a signature with the `RSAPrivateKey` like this:

```elixir
iex(3)> message = "A very important message."
"A very important message."

ex(4)> {:ok, signature} = ExPublicKey.sign(message, rsa_private_key)
{:ok, <<...>>}
```

### Verify signature with RSA public key

```elixir
iex(5)> {:ok, valid} = ExPublicKey.verify(message, signature, rsa_public_key)
{:ok, true}
```

### Encrypt with RSA public key

```elixir
iex(6)> clear_text = "A super important message"
"A super important message"
iex(7)> {:ok, cipher_text} = ExPublicKey.encrypt_public(clear_text, rsa_public_key)
{:ok, "Lmbv...HQ=="}
```

### Decrypt with RSA private key

```elixir
iex(8)> {:ok, decrypted_clear_text} = ExPublicKey.decrypt_private(cipher_text, rsa_private_key)
{:ok, "A super important message"}
```

## Using ExCrypto

The `ExCrypto` module provides relatively functions for AES cryptography operations.

### Generate AES keys

Generate a new 128 bit AES key like this:

```elixir
iex(1)> {:ok, aes_128_key} = ExCrypto.generate_aes_key(:aes_128, :bytes)
{:ok, <<...>>}
```

Often it's more convenient to handle the key as a base64 encoded string and you can generate a new key, already encoded as a base64 unicode string like this:

```elixir
iex(2)> {:ok, aes_128_key} = ExCrypto.generate_aes_key(:aes_128, :base64)
{:ok,
 "deGqaW9gP1_0WlSomf2pZDzeyGcitSmfXYu7ygTsypsrSmvTVfl7ANQsTWc30TP9IftiBnmDlqkuU1ARzAN82Fo1NMJhvVi3iWkzYe9yusm0s3ymUh4Hs2O7oZCgJeavFwuHgrpk_79nyfe3HkSNoAVjNWv0ImOmLyClrPIa3qk="}
 ```

 You can also generate 192/256 bit AES keys like this:

 ```elixir
 iex(3)> {:ok, aes_192_key} = ExCrypto.generate_aes_key(:aes_192, :base64)
{:ok,
 "P173Su55_bFR4WEf4SmKC4yKAX-IT9-83rbS6RSIPxEHf7uTEvyr969C3ZCkbSh5dJrWd35zjYQM-l5DpGzdIztxCqvN9myGYUdrfn9D2PRh9Y7XgQWRqYJ6FE67EHcNgJWrxEQ_HRt5jBczoY-34AZAN3RVcVqXrwGZw6ISJcyKVc30nJOBS9N4QeQWw2bPrppfzA43-_hAVfjEKCUyPzi2zlG2WUsaeKS4vOOmVAzkC0IPbONqVtzlxiFwbr7I"}

iex(4)> {:ok, aes_256_key} = ExCrypto.generate_aes_key(:aes_256, :base64)
{:ok,
 "Bs_BzhuwseEA8ZUvuEY0mq9Rmlv6cSoU_RaYD14Q62HiN_kJ4FiaW0YYppf1ffYPQ56xuitxQtYAnaeP-Q5l1WPh5aExdwCG_PUm5g-MlOUA1XSSP2RvuQqAiHzazIzjGVSIcl0Gr7TSLPOoIQrPshMNaA4j3SGZ3lAOqO1quvXtDn-9Sxwr5dwV7VzOIvXRwb0GbZeYp8lnVJgeqHl8cEhUTfT_h9Pm7tU2CFeHZCDK8ntFT_t4q6VlcBcvw_Pj3CGcVSmpmCHMKW1brt6jXGBijqSTdbjYDZnCx2Q44VoYqMMZ1U2GnVyjc-ZuwugwGGqQ7UEqV_TOMjbK6Oxx-Q=="}
 ```

 In both examples the `:bytes` atom can be substituted for `:base64` if you wish to receive your key as a `bitstring` rather than as a base64 encoded unicode string.

 As you can see the keys grow longer in order of bit length.  A 128 bit key is more than sufficient for most applications but if you are slightly more paranoid than average use a 192 bit key.

 If your paranoia knows no bounds or you are protecting state secrets from nation-state owned quantum computers use a 256 bit key.

 If you are concerned about hyper-advanced aliens with quantum computers you might need a longer key. Enterprise grade keys such as this can be generated upon request in the context of a consulting agreement.  For this application we recommend at least a 612 bit key.

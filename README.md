# ExCrypto

A wrapper around the Erlang `crypto` and `public_key` modules for elixir.

## Using ExPublicKey

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
{:ok, "Lmbvof7...hobHQ=="}
```

### Decrypt with RSA private key

```elixir
iex(8)> {:ok, decrypted_clear_text} = ExPublicKey.decrypt_private(cipher_text, rsa_private_key)
{:ok, "A super important message"}
```

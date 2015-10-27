# ExCrypto

A wrapper around the Erlang `crypto` and `public_key` modules for elixir.

## Using ExPublicKey

First load the public/private RSA keys from disk:

```elixir
{:ok, rsa_private_key} = ExPublicKey.load("/path/to/rsa_private_key.pem")
{:ok, rsa_public_key} = ExPublicKey.load("/path/to/rsa_public_key.pem")
```

### Sign with RSA private key

To create a signature with the `RSAPrivateKey` like this:

```elixir
{:ok, signature} = ExPublicKey.sign(message, rsa_private_key)
```

### Verify signature with RSA public key

```elixir
{:ok, valid} = ExPublicKey.verify(message, rsa_public_key)
```

### Encrypt with RSA public key

```elixir
{:ok, cipher_text} = ExPublicKey.encrypt_public(clear_text, rsa_public_key)
```

### Decrypt with RSA private key

```elixir
{:ok, decrypted_clear_text} = ExPublicKey.decrypt_private(cipher_text, rsa_private_key)
```

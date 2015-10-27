defmodule ExPublicKeyTest do
  use ExUnit.Case
  alias ExPublicKey.RSAPublicKey, as: RSAPublicKey
  alias ExPublicKey.RSAPrivateKey, as: RSAPrivateKey

  setup do
    # generate a RSA key pair
    # generate a unique temp file name
    rand_string = ExCrypto.rand_chars(4)
    rsa_private_key_path = "/tmp/test_ex_crypto_rsa_private_key_#{rand_string}.pem"
    rsa_public_key_path = "/tmp/test_ex_crypto_rsa_public_key_#{rand_string}.pem"
    
    # generate the RSA private key with openssl
    System.cmd(
      "openssl", ["genrsa", "-out", rsa_private_key_path, "2048"])

    # export the RSA public key to a file with openssl
    System.cmd(
      "openssl", ["rsa", "-in", rsa_private_key_path, "-outform", "PEM", "-pubout", "-out", rsa_public_key_path])

    on_exit fn ->
      # cleanup: delete the temp keys
      File.rm!(rsa_private_key_path)
      File.rm!(rsa_public_key_path)
    end

    {:ok, rsa_private_key_path: rsa_private_key_path, rsa_public_key_path: rsa_public_key_path}
  end

  test "read RSA keys in PEM format", context do

    # IO.inspect context
    # load the private key
    {:ok, priv_key_string} = File.read(context[:rsa_private_key_path])
    rsa_priv_key = ExPublicKey.loads!(priv_key_string)
    assert(is_map(rsa_priv_key))
    assert(rsa_priv_key.__struct__ == RSAPrivateKey)

    # load the public key
    {:ok, pub_key_string} = File.read(context[:rsa_public_key_path])
    rsa_pub_key = ExPublicKey.loads!(pub_key_string)
    assert(is_map(rsa_pub_key))
    assert(rsa_pub_key.__struct__ == RSAPublicKey)
  end

  test "try random string in key loads function and observe ExCrypto.Error" do
    assert_raise ExCrypto.Error, fn ->
      ExPublicKey.loads!(ExCrypto.rand_chars(1000))
    end
  end

  test "sign with private RSA key then verify signature with public RSA key", context do
    {:ok, rsa_priv_key} = ExPublicKey.load(context[:rsa_private_key_path])
    {:ok, rsa_pub_key} = ExPublicKey.load(context[:rsa_public_key_path])
    rand_chars = ExCrypto.rand_chars(16)
    msg = "This is a test message to sign, complete with some entropy (#{rand_chars})."
    {:ok, signature} = ExPublicKey.sign(msg, rsa_priv_key)
    {:ok, valid} = ExPublicKey.verify(msg, signature, rsa_pub_key)
    IO.inspect valid
    assert(valid)
  end

  test "RSA public_key encrypt and RSA private_key decrypt", context do
    {:ok, rsa_priv_key} = ExPublicKey.load(context[:rsa_private_key_path])
    {:ok, rsa_pub_key} = ExPublicKey.load(context[:rsa_public_key_path])
    rand_chars = ExCrypto.rand_chars(16)
    plain_text = "This is a test message to encrypt, complete with some entropy (#{rand_chars})."
    
    {:ok, cipher_text} = ExPublicKey.encrypt_public(plain_text, rsa_pub_key)
    assert(cipher_text != plain_text)

    {:ok, decrypted_plain_text} = ExPublicKey.decrypt_private(cipher_text, rsa_priv_key)
    assert(decrypted_plain_text == plain_text)
  end

  test "RSA private_key encrypt and RSA public_key decrypt", context do
    {:ok, rsa_priv_key} = ExPublicKey.load(context[:rsa_private_key_path])
    {:ok, rsa_pub_key} = ExPublicKey.load(context[:rsa_public_key_path])
    rand_chars = ExCrypto.rand_chars(16)
    plain_text = "This is a test message to encrypt, complete with some entropy (#{rand_chars})."
    
    {:ok, cipher_text} = ExPublicKey.encrypt_private(plain_text, rsa_priv_key)
    assert(cipher_text != plain_text)

    {:ok, decrypted_plain_text} = ExPublicKey.decrypt_public(cipher_text, rsa_pub_key)
    assert(decrypted_plain_text == plain_text)
  end

  test "provoke exception from Erlang that must be handled" do
    case ExPublicKey.sign("chuck norris", :sha256, "not really a key") do
      {:ok, signature} ->
        assert false, "this should have provoked an error: #{inspect signature}"
      {:error, reason} ->
        IO.inspect reason
        assert true, "the right error was provoked: #{reason}"
      {:error, error, stack_trace} ->
        IO.inspect error
        assert false, "the wrong error was provoked: #{error.message}"
      x ->
        # IO.inspect x
        assert false, "something else happened"
    end
  end

end

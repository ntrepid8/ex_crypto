defmodule ExPublicKeyTest do
  use ExUnit.Case

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
    signature = ExPublicKey.sign(msg, rsa_priv_key)
    assert(ExPublicKey.verify(msg, signature, rsa_pub_key))
  end

end

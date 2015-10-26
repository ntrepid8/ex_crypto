defmodule ExCryptoTest do
  use ExUnit.Case

  test "the truth" do
    assert 1 + 1 == 2
  end

  def run_rand_char_test() do
    rand_char_count = :crypto.rand_uniform(1, 100)
    rand_string = ExCrypto.rand_chars(rand_char_count)
    assert(String.length(rand_string) == rand_char_count)
  end
  
  test "generate random characters" do
    for n <- 1..100, do: run_rand_char_test()
  end

  test "generate random integers and test randomness" do
    set_size = 100000
    random_ints = for n <- 1..set_size, do: ExCrypto.rand_int(1, 100)

    # do cursory check for randomness, average should be very near 50
    average = Enum.sum(random_ints) / set_size
    assert(average > 49.5)
    assert(average < 50.5)
  end

  test "read RSA private key in PEM format" do

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

    {:ok, priv_key_string} = File.read(rsa_private_key_path)
    rsa_priv_key = ExPublicKey.loads(priv_key_string)
    assert(is_map(rsa_priv_key))
    assert(rsa_priv_key.__struct__ == RSAPrivateKey)

    # cleanup: delete the temp keys
    File.rm!(rsa_private_key_path)
    File.rm!(rsa_public_key_path)
  end
  
end

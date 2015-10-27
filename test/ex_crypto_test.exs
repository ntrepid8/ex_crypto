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

  test "generate 128 bit AES key as bytes" do
    {:ok, aes_128_key} = ExCrypto.generate_aes_key(:aes_128, :bytes)
    assert(Kernel.is_bitstring(aes_128_key))
    assert(byte_size(aes_128_key) == 16)
    assert(bit_size(aes_128_key) == 128)
  end

  test "generate 128 bit AES key as base64" do
    {:ok, aes_128_key} = ExCrypto.generate_aes_key(:aes_128, :base64)
    assert(Kernel.is_bitstring(aes_128_key))
    assert(String.length(aes_128_key) == 24)
  end

  test "generate 192 bit AES key as bytes" do
    {:ok, aes_192_key} = ExCrypto.generate_aes_key(:aes_192, :bytes)
    assert(Kernel.is_bitstring(aes_192_key))
    assert(byte_size(aes_192_key) == 24)
    assert(bit_size(aes_192_key) == 192)
  end

  test "generate 192 bit AES key as base64" do
    {:ok, aes_192_key} = ExCrypto.generate_aes_key(:aes_192, :base64)
    assert(Kernel.is_bitstring(aes_192_key))
    assert(String.length(aes_192_key) == 32)
  end

  test "generate 256 bit AES key as bytes" do
    {:ok, aes_256_key} = ExCrypto.generate_aes_key(:aes_256, :bytes)
    assert(Kernel.is_bitstring(aes_256_key))
    assert(byte_size(aes_256_key) == 32)
    assert(bit_size(aes_256_key) == 256)
  end

  test "generate 256 bit AES key as base64" do
    {:ok, aes_256_key} = ExCrypto.generate_aes_key(:aes_256, :base64)
    assert(Kernel.is_bitstring(aes_256_key))
    assert(String.length(aes_256_key) == 44)
  end

  test "test aes_gcm encrypt with 128 bit key" do
    {:ok, aes_128_key} = ExCrypto.generate_aes_key(:aes_128, :bytes)
    {:ok, iv} = ExCrypto.rand_bytes(16)
    clear_text = "a very secret message"
    a_data = "the auth and associated data"

    # encrypt
    {:ok, {cipher_text, cipher_tag}} = ExCrypto.encrypt(aes_128_key, iv, a_data, clear_text)
    assert(clear_text != cipher_text)

    # decrypt
    {:ok, decrypted_clear_text} = ExCrypto.decrypt(aes_128_key, iv, a_data, cipher_text, cipher_tag)
    assert(decrypted_clear_text == clear_text)
  end

end

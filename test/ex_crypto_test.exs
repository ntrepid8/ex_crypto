defmodule ExCryptoTest do
  use ExUnit.Case
  doctest ExCrypto

  test "the truth" do
    assert 1 + 1 == 2
  end

  def run_rand_char_test() do
    rand_char_count = :rand.uniform(100)
    rand_string = ExCrypto.rand_chars(rand_char_count)
    assert(String.length(rand_string) == rand_char_count)
  end

  test "generate random characters" do
    for _n <- 1..100, do: run_rand_char_test()
  end

  test "generate random integers and test randomness" do
    set_size = 100_000
    random_ints = for _n <- 1..set_size, do: ExCrypto.rand_int(0, 100)

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

  test "aes_gcm encrypt with 128 bit key" do
    {:ok, aes_128_key} = ExCrypto.generate_aes_key(:aes_128, :bytes)
    {:ok, iv} = ExCrypto.rand_bytes(16)
    clear_text = "a very secret message"
    a_data = "the auth and associated data"

    # encrypt
    {:ok, {ad, payload}} = ExCrypto.encrypt(aes_128_key, a_data, iv, clear_text)
    {_c_iv, cipher_text, cipher_tag} = payload
    assert(clear_text != cipher_text)

    # decrypt
    {:ok, decrypted_clear_text} = ExCrypto.decrypt(aes_128_key, ad, iv, cipher_text, cipher_tag)
    assert(decrypted_clear_text == clear_text)
  end

  test "test aes_gcm encrypt with auto-IV (128 bit key)" do
    {:ok, aes_128_key} = ExCrypto.generate_aes_key(:aes_128, :bytes)

    clear_text = "a very secret message"
    a_data = "the auth and associated data"

    # encrypt
    {:ok, {ad, payload}} = ExCrypto.encrypt(aes_128_key, a_data, clear_text)
    {iv, cipher_text, cipher_tag} = payload
    assert(byte_size(iv) == 16)
    assert(byte_size(cipher_tag) == 16)
    assert(clear_text != cipher_text)

    # decrypt
    {:ok, decrypted_clear_text} = ExCrypto.decrypt(aes_128_key, ad, iv, cipher_text, cipher_tag)
    assert(decrypted_clear_text == clear_text)
  end

  test "test aes_gcm encrypt with auto-IV (256 bit key)" do
    {:ok, aes_256_key} = ExCrypto.generate_aes_key(:aes_256, :bytes)

    clear_text = "a very secret message"
    a_data = "the auth and associated data"

    # encrypt
    {:ok, {ad, payload}} = ExCrypto.encrypt(aes_256_key, a_data, clear_text)
    {iv, cipher_text, cipher_tag} = payload
    assert(byte_size(iv) == 16)
    assert(byte_size(cipher_tag) == 16)
    assert(clear_text != cipher_text)

    # decrypt
    {:ok, decrypted_clear_text} = ExCrypto.decrypt(aes_256_key, ad, iv, cipher_text, cipher_tag)
    assert(decrypted_clear_text == clear_text)
  end

  test "package AES GCM payload" do
    {:ok, aes_256_key} = ExCrypto.generate_aes_key(:aes_256, :bytes)

    clear_text = "a very secret message"
    a_data = "the auth and associated data"

    # encrypt
    {:ok, {_ad, payload}} = ExCrypto.encrypt(aes_256_key, a_data, clear_text)
    {iv, cipher_text, cipher_tag} = payload
    assert(byte_size(iv) == 16)
    assert(byte_size(cipher_tag) == 16)
    assert(clear_text != cipher_text)

    # encode payload
    {:ok, payload} = ExCrypto.encode_payload(iv, cipher_text, cipher_tag)

    # decode_payload
    {:ok, {piv, pc_text, pc_tag}} = ExCrypto.decode_payload(payload)
    assert(iv == piv)
    assert(cipher_text == pc_text)
    assert(cipher_tag == pc_tag)
  end

  test "test aes_cbc encrypt with auto-IV (256 bit key)" do
    {:ok, aes_256_key} = ExCrypto.generate_aes_key(:aes_256, :bytes)

    clear_text = "secret_message"
    # encrypt
    {:ok, {iv, cipher_text}} = ExCrypto.encrypt(aes_256_key, clear_text)
    assert(byte_size(iv) == 16)
    assert(clear_text != cipher_text)

    # decrypt
    {:ok, decrypted_clear_text} = ExCrypto.decrypt(aes_256_key, iv, cipher_text)
    assert(decrypted_clear_text == clear_text)
  end

  test "errors with bad key length" do
    {:ok, aes_bad_raw_key} = ExCrypto.rand_bytes(27)
    aes_bad_key = Base.url_encode64(aes_bad_raw_key)

    clear_text = "secret_message"
    # encrypt
    {:error, error_message} = ExCrypto.encrypt(aes_bad_key, clear_text)
    assert(is_binary(error_message))
  end

  test "errors with bad iv length " do
    {:ok, aes_256_key} = ExCrypto.generate_aes_key(:aes_256, :bytes)
    {:ok, bad_iv} = ExCrypto.rand_bytes(17)
    clear_text = "secret_message"
    # encrypt
    {:error, error_message} =
      ExCrypto.encrypt(aes_256_key, clear_text, %{initialization_vector: bad_iv})

    assert(is_binary(error_message))
  end
end

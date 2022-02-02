defmodule ExPublicKeyTest do
  use ExUnit.Case
  alias ExPublicKey.RSAPublicKey, as: RSAPublicKey
  alias ExPublicKey.RSAPrivateKey, as: RSAPrivateKey

  setup do
    # generate a RSA key pair
    # generate a unique temp file name
    rand_string = ExCrypto.rand_chars(4)
    rsa_private_key_path = "/tmp/test_ex_crypto_rsa_private_key_#{rand_string}.pem"
    rsa_private_key_path_der = "/tmp/test_ex_crypto_rsa_private_key_#{rand_string}.der"
    rsa_public_key_path = "/tmp/test_ex_crypto_rsa_public_key_#{rand_string}.pem"
    rsa_public_key_path_der = "/tmp/test_ex_crypto_rsa_public_key_#{rand_string}.der"
    rsa_secure_private_key_path = "/tmp/test_ex_crypto_rsa_secure_private_key_#{rand_string}.pem"

    sys_cmd_opts = [stderr_to_stdout: true]

    # generate the RSA private key with openssl
    {_, 0} =
      System.cmd("openssl", ["genrsa", "-out", rsa_private_key_path, "2048"], sys_cmd_opts)

    # export the RSA public key to a file with openssl
    {_, 0} =
      System.cmd("openssl", [
        "rsa",
        "-in",
        rsa_private_key_path,
        "-outform",
        "PEM",
        "-pubout",
        "-out",
        rsa_public_key_path
      ], sys_cmd_opts)

    # generate a passphrase protected RSA private key with openssl
    {_, 0} =
      System.cmd("openssl", [
        "genrsa",
        "-out",
        rsa_secure_private_key_path,
        "-passout",
        "pass:#{rand_string}",
        "2048"
      ], sys_cmd_opts)

    # save DER encoded form
    {_, 0} =
      System.cmd("openssl", [
        "rsa",
        "-in",
        rsa_private_key_path,
        "-outform",
        "DER",
        "-out",
        rsa_private_key_path_der],
        sys_cmd_opts)

    # save DER encoded form (pub)
    {_, 0} =
      System.cmd("openssl", [
        "rsa",
        "-in",
        rsa_private_key_path,
        "-pubout",
        "-outform",
        "DER",
        "-out",
        rsa_public_key_path_der],
        sys_cmd_opts)

    on_exit(fn ->
      # cleanup: delete the temp keys
      File.rm!(rsa_private_key_path)
      File.rm!(rsa_public_key_path)
      File.rm!(rsa_private_key_path_der)
      File.rm!(rsa_public_key_path_der)
      File.rm!(rsa_secure_private_key_path)
    end)

    {:ok,
     [
       rsa_private_key_path: rsa_private_key_path,
       rsa_private_key_path_der: rsa_private_key_path_der,
       rsa_public_key_path: rsa_public_key_path,
       rsa_public_key_path_der: rsa_public_key_path_der,
       rsa_secure_private_key_path: rsa_secure_private_key_path,
       passphrase: rand_string,
     ]}
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

  test "converts RSA keys to PEM format and back", _context do
    {:ok, rsa_priv_key} = ExPublicKey.generate_key()
    {:ok, priv_key_string} = ExPublicKey.pem_encode(rsa_priv_key)

    rsa_priv_key_decoded = ExPublicKey.loads!(priv_key_string)
    assert(is_map(rsa_priv_key_decoded))
    assert(rsa_priv_key_decoded == rsa_priv_key)
  end

  test "read secure RSA keys", context do
    {:ok, secure_priv_key_string} = File.read(context[:rsa_secure_private_key_path])
    secure_rsa_priv_key = ExPublicKey.loads!(secure_priv_key_string, context[:passphrase])
    assert(is_map(secure_rsa_priv_key))
    assert(secure_rsa_priv_key.__struct__ == RSAPrivateKey)
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

  test "RSA public_key encrypt and RSA private_key decrypt (url_safe: false)", context do
    {:ok, rsa_priv_key} = ExPublicKey.load(context[:rsa_private_key_path])
    {:ok, rsa_pub_key} = ExPublicKey.load(context[:rsa_public_key_path])
    rand_chars = ExCrypto.rand_chars(16)
    plain_text = "This is a test message to encrypt, complete with some entropy (#{rand_chars})."

    # don't use url_safe encoding
    opts = [url_safe: false]

    {:ok, cipher_text} = ExPublicKey.encrypt_public(plain_text, rsa_pub_key, opts)
    assert(cipher_text != plain_text)

    {:ok, decrypted_plain_text} = ExPublicKey.decrypt_private(cipher_text, rsa_priv_key, opts)
    assert(decrypted_plain_text == plain_text)
  end

  test "RSAPrivateKey encode_der", context do
    # load openssl DER encoded file
    rsa_private_key_der = File.read!(context.rsa_private_key_path_der)

    {:ok, rsa_priv_key} = ExPublicKey.load(context.rsa_private_key_path)
    {:ok, der_encoded} = RSAPrivateKey.encode_der(rsa_priv_key)

    # compare our DER encoded value to the openssl DER encoded value
    assert der_encoded == rsa_private_key_der
  end

  test "RSAPublicKey encode_der", context do
    # load openssl DER encoded file
    rsa_public_key_der = File.read!(context.rsa_public_key_path_der)

    {:ok, rsa_pub_key} = ExPublicKey.load(context.rsa_public_key_path)
    {:ok, der_encoded} = RSAPublicKey.encode_der(rsa_pub_key)

    # compare our DER encoded value to the openssl DER encoded value
    assert der_encoded == rsa_public_key_der
  end

  test "RSAPrivateKey get_fingerprint/2 (sha256)", context do
    # compute sha256 fingerprint w/ openssl
    rsa_private_key_fingerprint_sha256 =
      to_charlist("openssl sha256 #{context.rsa_private_key_path} 2> /dev/null")
      |> :os.cmd()
      |> to_string()

    {:ok, rsa_priv_key} = ExPublicKey.load(context.rsa_private_key_path)
    fingerprint = RSAPrivateKey.get_fingerprint(rsa_priv_key, format: :sha256)

    # verify computed value matches openssl
    rsa_private_key_fingerprint_sha256 =~ fingerprint
  end

  test "RSAPublicKey get_fingerprint/2 (sha256)", context do
    # compute sha256 fingerprint w/ openssl
    rsa_public_key_fingerprint_sha256 =
      to_charlist("openssl sha256 #{context.rsa_public_key_path_der}")
      |> :os.cmd()
      |> to_string()

    {:ok, rsa_pub_key} = ExPublicKey.load(context.rsa_public_key_path)
    fingerprint = RSAPublicKey.get_fingerprint(rsa_pub_key, format: :sha256)

    # verify computed value matches openssl
    rsa_public_key_fingerprint_sha256 =~ fingerprint
  end

  test "RSAPublicKey get_fingerprint/2 (md5)", context do
    # compute md5 fingerprint w/ openssl
    rsa_public_key_fingerprint_md5 =
      to_charlist("openssl md5 #{context.rsa_public_key_path_der}")
      |> :os.cmd()
      |> to_string()

    {:ok, rsa_pub_key} = ExPublicKey.load(context.rsa_public_key_path)
    fingerprint = RSAPublicKey.get_fingerprint(rsa_pub_key, format: :md5)

    # verify computed value matches openssl
    rsa_public_key_fingerprint_md5 =~ fingerprint
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

  test "RSA private_key encrypt and RSA public_key decrypt using generated keys", _context do
    {:ok, rsa_priv_key} = ExPublicKey.generate_key()
    {:ok, rsa_pub_key} = ExPublicKey.public_key_from_private_key(rsa_priv_key)
    rand_chars = ExCrypto.rand_chars(16)
    plain_text = "This is a test message to encrypt, complete with some entropy (#{rand_chars})."

    {:ok, cipher_text} = ExPublicKey.encrypt_private(plain_text, rsa_priv_key)
    assert(cipher_text != plain_text)

    {:ok, decrypted_plain_text} = ExPublicKey.decrypt_public(cipher_text, rsa_pub_key)
    assert(decrypted_plain_text == plain_text)
  end

  test "RSA private_key encrypt and RSA public_key decrypt  (url_safe: false)", context do
    {:ok, rsa_priv_key} = ExPublicKey.load(context[:rsa_private_key_path])
    {:ok, rsa_pub_key} = ExPublicKey.load(context[:rsa_public_key_path])
    rand_chars = ExCrypto.rand_chars(16)
    plain_text = "This is a test message to encrypt, complete with some entropy (#{rand_chars})."

    # don't use url_safe encoding
    opts = [url_safe: false]

    {:ok, cipher_text} = ExPublicKey.encrypt_private(plain_text, rsa_priv_key, opts)
    assert(cipher_text != plain_text)

    {:ok, decrypted_plain_text} = ExPublicKey.decrypt_public(cipher_text, rsa_pub_key, opts)
    assert(decrypted_plain_text == plain_text)
  end

  test "provoke exception from Erlang that must be handled" do
    case ExPublicKey.sign("chuck norris", :sha256, "not really a key") do
      {:ok, signature} ->
        assert false, "this should have provoked an error: #{inspect(signature)}"

      {:error, reason} ->
        assert true, "the right error was provoked: #{inspect reason}"

      {:error, error, _stack_trace} ->
        assert false, "the wrong error was provoked: #{inspect error}"

      _x ->
        # IO.inspect x
        assert false, "something else happened"
    end
  end

  test "sign and verify a JSON payload", context do
    # load the RSA keys from a file on disk
    rsa_priv_key = ExPublicKey.load!(context[:rsa_private_key_path])
    rsa_pub_key = ExPublicKey.load!(context[:rsa_public_key_path])

    # the JSON
    msg = %{"name_first" => "Chuck", "name_last" => "Norris"}

    # serialize the JSON
    msg_serialized = Poison.encode!(msg)

    # generate time-stamp
    ts = ExCrypto.universal_time(:unix)

    # add a time-stamp
    ts_msg_serialized = "#{ts}|#{msg_serialized}"

    # generate a secure hash using SHA256 and sign the message with the private key
    {:ok, signature} = ExPublicKey.sign(ts_msg_serialized, rsa_priv_key)

    # combine payload
    payload = "#{ts}|#{msg_serialized}|#{Base.url_encode64(signature)}"

    # pretend transmit the message via HTTPS...
    # pretend receive the message via HTTPS...

    # break up the payload
    parts = String.split(payload, "|")
    recv_ts = Enum.fetch!(parts, 0)
    recv_msg_serialized = Enum.fetch!(parts, 1)
    {:ok, recv_sig} = Enum.fetch!(parts, 2) |> Base.url_decode64()

    # pretend ensure the time-stamp is not too old (or from the future)...
    # it should probably no more than 5 minutes old, and no more than 15 minutes in the future

    # verify the signature
    {:ok, sig_valid} =
      ExPublicKey.verify("#{recv_ts}|#{recv_msg_serialized}", recv_sig, rsa_pub_key)

    assert(sig_valid)

    # un-serialize the JSON
    recv_msg_unserialized = Poison.Parser.parse!(recv_msg_serialized)
    assert(msg == recv_msg_unserialized)
  end

  test "inspecting a private key doesn't expose it", %{rsa_private_key_path: path} do
    {:ok, priv_key} = ExPublicKey.load(path)
    refute String.contains?(inspect(priv_key), to_string(priv_key.prime_one))
  end

  test "inspect/2", context do
    # load the keys
    priv_key = ExPublicKey.load!(context.rsa_private_key_path)
    pub_key = ExPublicKey.load!(context.rsa_public_key_path)

    # generate the fingerprints
    priv_key_fp = RSAPrivateKey.get_fingerprint(priv_key, colons: true)
    pub_key_fp = RSAPublicKey.get_fingerprint(pub_key, colons: true)

    # get the string results of inspect
    priv_key_inspect = inspect(priv_key)
    pub_key_inspect = inspect(pub_key)

    # verify private key
    assert priv_key_inspect =~ priv_key_fp
    assert String.starts_with?(priv_key_inspect, "#ExPublicKey.RSAPrivateKey<")
    assert String.ends_with?(priv_key_inspect, ">")

    # verify public key
    assert pub_key_inspect =~ pub_key_fp
    assert String.starts_with?(pub_key_inspect, "#ExPublicKey.RSAPublicKey<")
    assert String.ends_with?(pub_key_inspect, ">")
  end

end

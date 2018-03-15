defmodule ExPublicKey.RSAPublicKey do
  defstruct version: nil,
            public_modulus: nil,
            public_exponent: nil

  @type t :: %ExPublicKey.RSAPublicKey{
          version: atom,
          public_modulus: integer,
          public_exponent: integer
        }

  def from_sequence(rsa_key_seq) do
    %ExPublicKey.RSAPublicKey{}
    |> struct(
      public_modulus: elem(rsa_key_seq, 1),
      public_exponent: elem(rsa_key_seq, 2)
    )
  end

  def as_sequence(rsa_public_key) do
    case rsa_public_key do
      %ExPublicKey.RSAPublicKey{} ->
        {:ok,
         {
           :RSAPublicKey,
           Map.get(rsa_public_key, :public_modulus),
           Map.get(rsa_public_key, :public_exponent)
         }}

      _ ->
        {:error, "invalid ExPublicKey.RSAPublicKey: #{rsa_public_key}"}
    end
  end

  def get_fingerprint(rsa_public_key=%__MODULE__{}, opts \\ []) do
    # parse opts
    digest_type = Keyword.get(opts, :digest_type, :sha256)
    colons = Keyword.get(opts, :colons, false)

    # encode_der and hash
    with {:ok, der_encoded} <- encode_der(rsa_public_key),
         digest = :crypto.hash(digest_type, der_encoded),
         hex_fp = Base.encode16(digest, case: :lower),
      do: add_fingerprint_colons(hex_fp, colons)
  end

  def encode_der(rsa_public_key=%__MODULE__{}) do
    # hack to encode same defaults as openssl in SubjectPublicKeyInfo format
    with {:ok, key_sequence} <- as_sequence(rsa_public_key) do
      pem_entry = :public_key.pem_entry_encode(:SubjectPublicKeyInfo, key_sequence)
      der_encoded =
        :public_key.pem_encode([pem_entry])
        |> String.trim()
        |> String.split("\n")
        |> Enum.filter(fn(line) -> !String.contains?(line, "-----") end)
        |> Enum.join("")
        |> Base.decode64!()
      {:ok, der_encoded}
    end
  end

  def decode_der(der_encoded, opts \\ []) do
    # parse opts
    format = Keyword.get(opts, :format, :SubjectPublicKeyInfo) # also supports :RSAPublicKey

    # decode and parse
    :public_key.der_decode(format, der_encoded)
    |> from_der_encoded_0()
  end

  # Protocols

  defimpl Inspect do
    import Inspect.Algebra

    @doc """
    Formats the RSAPrivateKey and includes the SHA256 fingerprint.

    example:
    ```
    #ExPublicKey.RSAPublicKey<
     fingerprint_sha256=7a:40:1c:b9:4b:b8:a5:bb:6b:98:b6:1b:8b:7a:24:8d:45:9b:e5:54
      17:7e:66:26:7e:95:11:9d:39:14:7b:b2>
    ```
    """
    def inspect(data, _opts) do
      fp_opts = [format: :sha256, colons: true]

      fp_sha256_parts_doc =
        ExPublicKey.RSAPublicKey.get_fingerprint(data, fp_opts)
        |> String.split(":")
        |> fold_doc(fn(doc, acc) -> glue(doc, ":", acc) end)

      fp_sha256_doc =
        glue("fingerprint_sha256=", "", fp_sha256_parts_doc)
        |> group()
        |> nest(2)

      glue("#ExPublicKey.RSAPublicKey<", "", fp_sha256_doc)
      |> concat(">")
      |> nest(2)
    end
  end

  # Helpers

  defp add_fingerprint_colons(data, true) do
    case String.valid?(data) do
      true ->
        String.splitter(data, "", trim: true)
        |> Enum.chunk(2)
        |> Enum.map(fn(chunk_list) ->
          Enum.join(chunk_list, "")
        end)
        |> Enum.join(":")
      false ->
        data
    end
  end
  defp add_fingerprint_colons(data, _false) do
    data
  end

  def from_der_encoded_0({:SubjectPublicKeyInfo, _, der_key}) do
    with {:RSAPublicKey, pub_mod, pub_exp} <- :public_key.der_decode(:RSAPublicKey, der_key),
      do: from_der_encoded_0({:RSAPublicKey, pub_mod, pub_exp})
  end
  def from_der_encoded_0({:RSAPublicKey, pub_mod, pub_exp}) do
    rsa_pub_key = from_sequence({:RSAPublicKey, pub_mod, pub_exp})
    {:ok, rsa_pub_key}
  end
  def from_der_encoded_0(_other) do
    {:error, :invalid_public_key}
  end

end

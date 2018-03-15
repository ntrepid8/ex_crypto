defmodule ExPublicKey.RSAPrivateKey do
  defstruct version: nil,
            public_modulus: nil,
            public_exponent: nil,
            private_exponent: nil,
            prime_one: nil,
            prime_two: nil,
            exponent_one: nil,
            exponent_two: nil,
            ctr_coefficient: nil,
            other_prime_infos: nil

  @type t :: %ExPublicKey.RSAPrivateKey{
          version: atom,
          public_modulus: integer,
          public_exponent: integer,
          private_exponent: integer,
          prime_one: integer,
          prime_two: integer,
          exponent_one: integer,
          exponent_two: integer,
          ctr_coefficient: integer,
          other_prime_infos: atom
        }

  def from_sequence(rsa_key_seq) do
    %ExPublicKey.RSAPrivateKey{}
    |> struct(
      version: maybe_convert_version_to_atom(elem(rsa_key_seq, 1)),
      public_modulus: elem(rsa_key_seq, 2),
      public_exponent: elem(rsa_key_seq, 3),
      private_exponent: elem(rsa_key_seq, 4),
      prime_one: elem(rsa_key_seq, 5),
      prime_two: elem(rsa_key_seq, 6),
      exponent_one: elem(rsa_key_seq, 7),
      exponent_two: elem(rsa_key_seq, 8),
      ctr_coefficient: elem(rsa_key_seq, 9),
      other_prime_infos: elem(rsa_key_seq, 10)
    )
  end

  def as_sequence(rsa_private_key) do
    case rsa_private_key do
      %__MODULE__{} ->
        {:ok,
         {
           :RSAPrivateKey,
           Map.get(rsa_private_key, :version),
           Map.get(rsa_private_key, :public_modulus),
           Map.get(rsa_private_key, :public_exponent),
           Map.get(rsa_private_key, :private_exponent),
           Map.get(rsa_private_key, :prime_one),
           Map.get(rsa_private_key, :prime_two),
           Map.get(rsa_private_key, :exponent_one),
           Map.get(rsa_private_key, :exponent_two),
           Map.get(rsa_private_key, :ctr_coefficient),
           Map.get(rsa_private_key, :other_prime_infos)
         }}

      _ ->
        {:error, "invalid ExPublicKey.RSAPrivateKey: #{inspect(rsa_private_key)}"}
    end
  end

  def decode_der(der_encoded) do
    key_sequence = :public_key.der_decode(:RSAPrivateKey, der_encoded)
    rsa_private_key = from_sequence(key_sequence)
    {:ok, rsa_private_key}
  end

  def encode_der(rsa_private_key=%__MODULE__{}) do
    with {:ok, key_sequence} <- as_sequence(rsa_private_key) do
      der_encoded = :public_key.der_encode(:RSAPrivateKey, key_sequence)
      {:ok, der_encoded}
    end
  end

  def get_public(rsa_private_key=%__MODULE__{}) do
    %ExPublicKey.RSAPublicKey{
      public_modulus: rsa_private_key.public_modulus,
      public_exponent: rsa_private_key.public_exponent,
    }
  end

  def get_fingerprint(rsa_private_key=%__MODULE__{}, opts \\ []) do
    get_public(rsa_private_key)
    |> ExPublicKey.RSAPublicKey.get_fingerprint(opts)
  end

  # Protocols

  defimpl Inspect do
    import Inspect.Algebra

    @doc """
    Formats the RSAPrivateKey without exposing any private information.

    example:
    ```
    #ExPublicKey.RSAPrivateKey<
     fingerprint_sha256=7a:40:1c:b9:4b:b8:a5:bb:6b:98:b6:1b:8b:7a:24:8d:45:9b:e5:54
      17:7e:66:26:7e:95:11:9d:39:14:7b:b2>
    ```
    """
    def inspect(data, _opts) do
      fp_opts = [format: :sha256, colons: true]

      fp_sha256_parts_doc =
        ExPublicKey.RSAPrivateKey.get_fingerprint(data, fp_opts)
        |> String.split(":")
        |> fold_doc(fn(doc, acc) -> glue(doc, ":", acc) end)

      fp_sha256_doc =
        glue("fingerprint_sha256=", "", fp_sha256_parts_doc)
        |> group()
        |> nest(2)

      glue("#ExPublicKey.RSAPrivateKey<", "", fp_sha256_doc)
      |> concat(">")
      |> nest(2)
    end
  end

  # Helpers

  # Generating a RSA key on OTP 20.0 results in a RSAPrivateKey with version 0, which is the internal number that matches to :"two-prime".
  # Parsing this structure to PEM and then converting it back will yield a version not of 0, but of :"two-prime".
  # This conversion ensures it is always the symbol.
  defp maybe_convert_version_to_atom(0), do: :"two-prime"
  defp maybe_convert_version_to_atom(version), do: version
end

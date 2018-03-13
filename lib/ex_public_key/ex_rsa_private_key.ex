defmodule ExPublicKey.RSAPrivateKey do
  defimpl Inspect do
    def inspect(_data, _opts), do: "%ExPublicKey.RSAPrivateKey{}"
  end

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

  # Generating a RSA key on OTP 20.0 results in a RSAPrivateKey with version 0, which is the internal number that matches to :"two-prime".
  # Parsing this structure to PEM and then converting it back will yield a version not of 0, but of :"two-prime".
  # This conversion ensures it is always the symbol.
  defp maybe_convert_version_to_atom(0), do: :"two-prime"
  defp maybe_convert_version_to_atom(version), do: version
end

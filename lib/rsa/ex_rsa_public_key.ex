defmodule RSAPublicKey do
  defstruct version: nil,
            public_exponent: nil,
            public_modulus: nil

  @type t :: %RSAPublicKey{
    version: atom,
    public_exponent: integer,
    public_modulus: integer
  }

  def from_sequence(rsa_key_seq) do
    %RSAPublicKey{} |> struct(
      public_exponent: elem(rsa_key_seq, 1),
      public_modulus: elem(rsa_key_seq, 2)
    )
  end

  def as_sequence(rsa_public_key) do
    case rsa_public_key do
      %RSAPublicKey{} ->
        {:ok, {
          :RSAPublicKey,
          rsa_public_key.public_exponent,
          rsa_public_key.public_modulus,
        }}
      _ ->
        {:error, "invalid RSAPublicKey: #{rsa_public_key}"}
    end
  end

end

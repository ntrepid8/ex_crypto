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
end

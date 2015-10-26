defmodule RSAPrivateKey do
  defstruct version: nil,
            public_exponent: nil,
            public_modulus: nil,
            private_exponent: nil,
            prime_one: nil,
            prime_two: nil,
            exponent_one: nil,
            exponent_two: nil,
            ctr_coefficient: nil,
            other_prime_infos: nil

  @type t :: %RSAPrivateKey{
    version: atom,
    public_exponent: integer,
    public_modulus: integer,
    private_exponent: integer,
    prime_one: integer,
    prime_two: integer,
    exponent_one: integer,
    exponent_two: integer,
    ctr_coefficient: integer,
    other_prime_infos: atom
  }

  def from_sequence(rsa_key_seq) do
    %RSAPrivateKey{} |> struct(
      version: elem(rsa_key_seq, 1),
      public_exponent: elem(rsa_key_seq, 2),
      public_modulus: elem(rsa_key_seq, 3),
      private_exponent: elem(rsa_key_seq, 4),
      prime_one: elem(rsa_key_seq, 5),
      prime_two: elem(rsa_key_seq, 6),
      exponent_one: elem(rsa_key_seq, 7),
      exponent_two: elem(rsa_key_seq, 8),
      ctr_coefficient: elem(rsa_key_seq, 9),
      other_prime_infos: elem(rsa_key_seq, 10),
    )
  end

  def as_sequence(rsa_private_key) do
    {
      :RSAPrivateKey,
      rsa_private_key.version,
      rsa_private_key.public_exponent,
      rsa_private_key.public_modulus,
      rsa_private_key.private_exponent,
      rsa_private_key.prime_one,
      rsa_private_key.prime_two,
      rsa_private_key.exponent_one,
      rsa_private_key.exponent_two,
      rsa_private_key.ctr_coefficient,
      rsa_private_key.other_prime_infos,
    }
  end

end

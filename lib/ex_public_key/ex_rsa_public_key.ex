defmodule ExPublicKey.RSAPublicKey do

  defstruct [
    version: nil,
    public_modulus: nil,
    public_exponent: nil,
  ]

  @type t :: %ExPublicKey.RSAPublicKey{
    version: atom,
    public_modulus: integer,
    public_exponent: integer
  }

  def from_sequence(rsa_key_seq) do
    %ExPublicKey.RSAPublicKey{} |> struct(
      public_modulus: elem(rsa_key_seq, 1),
      public_exponent: elem(rsa_key_seq, 2)
    )
  end

  def as_sequence(rsa_public_key) do
    case rsa_public_key do
      %ExPublicKey.RSAPublicKey{} ->
        {:ok, {
          :RSAPublicKey,
          Map.get(rsa_public_key, :public_modulus),
          Map.get(rsa_public_key, :public_exponent),
        }}
      _ ->
        {:error, "invalid ExPublicKey.RSAPublicKey: #{rsa_public_key}"}
    end
  end

end

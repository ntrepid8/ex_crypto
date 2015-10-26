defmodule ExPublicKey do
  
  def loads(pem_string) do
    pem_entries = :public_key.pem_decode(pem_string)
    if length(pem_entries) > 1 do
      raise ArgumentError, message: "found multiple PEM entries, expected only 1"
    end
    pem_entry = Enum.at(pem_entries, 0)
    key_tup = :public_key.pem_entry_decode(pem_entry)
    case elem(key_tup, 0) do
      :RSAPrivateKey ->
        RSAPrivateKey.from_sequence(key_tup)
      :RSAPublicKey ->
        RSAPublicKey.from_sequence(key_tup)
    end
  end
end

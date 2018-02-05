defmodule ExCrypto.Error do
  defexception reason: nil

  def message(exception) do
    "ExCrypto.Error: #{exception.reason}"
  end
end

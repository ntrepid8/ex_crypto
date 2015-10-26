defmodule ExCrypto.Error do
  defexception [reason: nil]

  def message(exception) do
    "error: #{exception.reason}"
  end
end

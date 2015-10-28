defmodule ExCrypto.Mixfile do
  use Mix.Project

  def project do
    [app: :ex_crypto,
     version: "0.0.1",
     elixir: "~> 1.0",
     deps: deps]
  end

  def application do
    [applications: [:logger, :pipe, :tzdata]]
  end

  defp deps do
    [
      {:pipe, github: "batate/elixir-pipes"},
      {:poison, "~> 1.5"},
      {:timex, "~> 1.0.0-rc1"}
    ]
  end
end

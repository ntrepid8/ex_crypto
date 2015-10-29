defmodule ExCrypto.Mixfile do
  use Mix.Project

  def project do
    [app: :ex_crypto,
     version: "0.0.1",
     name: "ExCrypto",
     elixir: "~> 1.0",
     deps: deps,
     docs: [extras: ["README.md"]]
   ]
  end

  def application do
    [applications: [:logger, :pipe, :tzdata]]
  end

  defp deps do
    [
      {:pipe, github: "batate/elixir-pipes"},
      {:poison, "~> 1.5"},
      {:timex, "~> 1.0.0-rc1"},
      {:earmark, "~> 0.1", only: :dev},
      {:ex_doc, "~> 0.10", only: :dev}
    ]
  end
end

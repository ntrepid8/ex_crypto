defmodule ExCrypto.Mixfile do
  use Mix.Project

  def project do
    [app: :ex_crypto,
     version: "0.0.1",
     name: "ExCrypto",
     elixir: ">= 1.0.0",
     description: description,
     package: package,
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
      {:poison, ">= 1.0.0"},
      {:timex, ">= 0.19.0"},
      {:earmark, "~> 0.1", only: :dev},
      {:ex_doc, "~> 0.10", only: :dev}
    ]
  end

  defp description do
    """
    A wrapper around the Erlang Crypto module with sensible defaults for common tasks.
    """
  end

  defp package do
    [
      files: ["lib", "mix.exs", "README*", "readme*", "LICENSE*", "license*"],
      maintainers: ["Josh Austin"],
      licenses: ["MIT"],
      links: %{"Github" => "https://github.com/ntrepid8/ex_crypto",
               "Docs" => "https://ntrepid8.github.io/ex_crypto/extra-api-reference.html"}]
  end
end

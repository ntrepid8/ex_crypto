defmodule ExCrypto.Mixfile do
  use Mix.Project

  def project do
    [
      app: :ex_crypto,
      version: "0.9.0",
      name: "ExCrypto",
      elixir: ">= 1.4.2",
      description: description(),
      package: package(),
      deps: deps(),
      docs: [extras: ["README.md"]]
    ]
  end

  def application do
    [applications: applications(Mix.env())]
  end

  defp applications(:test) do
    applications(:prod)
  end

  defp applications(_) do
    [:logger, :crypto, :public_key]
  end

  defp deps do
    [
      {:poison, ">= 2.0.0"},
      {:dialyxir, "~> 0.5", only: [:dev], runtime: false},
      {:ex_doc, "~> 0.15", only: :dev}
    ]
  end

  defp description do
    """
    A wrapper around the Erlang Crypto module with sensible defaults for common tasks.
    """
  end

  defp package do
    [
      files: ["lib", "mix.exs", "README*", "LICENSE*", "CHANGELOG*"],
      maintainers: ["Josh Austin"],
      licenses: ["MIT"],
      links: %{
        "Github" => "https://github.com/ntrepid8/ex_crypto",
        "Docs" => "https://hexdocs.pm/ex_crypto/readme.html"
      }
    ]
  end
end

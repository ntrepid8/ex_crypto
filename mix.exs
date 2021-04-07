defmodule ExCrypto.Mixfile do
  use Mix.Project

  @source_url "https://github.com/ntrepid8/ex_crypto"
  @version "0.10.0"

  def project do
    [
      app: :ex_crypto,
      name: "ExCrypto",
      version: @version,
      elixir: ">= 1.4.2",
      package: package(),
      deps: deps(),
      docs: docs()
    ]
  end

  def application do
    [
      applications: applications(Mix.env())
    ]
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
      {:ex_doc, ">= 0.0.0", only: :dev, runtime: false}
    ]
  end

  defp package do
    [
      description:
        "A wrapper around the Erlang Crypto module with sensible defaults " <>
          "for common tasks.",
      files: ["lib", "mix.exs", "README*", "LICENSE*", "CHANGELOG*"],
      maintainers: ["Josh Austin"],
      licenses: ["MIT"],
      links: %{
        "Changelog" => "https://hexdocs.pm/ex_crypto/changelog.html",
        "GitHub" => @source_url
      }
    ]
  end

  defp docs do
    [
      extras: [
        "CHANGELOG.md",
        {:"LICENSE.md", [title: "License"]},
        "README.md"
      ],
      main: "readme",
      source_url: @source_url,
      source_ref: "#v{@version}",
      formatters: ["html"]
    ]
  end
end

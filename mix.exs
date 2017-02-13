defmodule ExCrypto.Mixfile do
  use Mix.Project

  def project do
    [app: :ex_crypto,
     version: "0.3.0",
     name: "ExCrypto",
     elixir: ">= 1.0.0",
     description: description,
     package: package,
     deps: deps,
     docs: [extras: ["README.md"]]
   ]
  end

  def application do
    [applications: applications(Mix.env)]
  end
  defp applications(:test) do
    applications(:prod) ++ [:tzdata]
  end
  defp applications(_) do
    [:logger, :pipe]
  end


  defp deps do
    [
      {:pipe, ">= 0.0.2"},
      {:poison, ">= 1.0.0"},
      {:timex, ">= 0.19.0", only: :test},
      {:earmark, "~> 0.1", only: :dev},
      {:dialyxir, "~> 0.4", only: [:dev], runtime: false},
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
      files: ["lib", "mix.exs", "README*", "LICENSE*", "CHANGELOG*"],
      maintainers: ["Josh Austin"],
      licenses: ["MIT"],
      links: %{"Github" => "https://github.com/ntrepid8/ex_crypto",
               "Docs" => "https://ntrepid8.github.io/ex_crypto/extra-api-reference.html"}]
  end
end

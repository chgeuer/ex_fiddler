defmodule Fiddler.MixProject do
  use Mix.Project

  def project do
    [
      app: :fiddler,
      version: "0.1.0",
      elixir: "~> 1.17",
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger, :inets, :ssl]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:req, "~> 0.5.7"},
      {:nimble_options, "~> 1.1"}
    ]
  end
end

defmodule Fiddler do
  require Logger

  @moduledoc """
  Fiddler module provides functions to attach the proxy server address and port to a `:req` request.
  """

  # TODO enable NimbleOptions.new!(...)
  @schema [
    ip: [type: :string, required: false],
    port: [type: :integer, required: false]
  ]

  @doc """
  Attaches the proxy server address and port to the request.
  """
  def attach(%Req.Request{} = req, opts \\ []) do
    case proxy_settings(opts) do
      nil ->
        req

      {:ok, ip, port} ->
        req
        |> Req.merge(
          connect_options: [
            # proxy_headers: [ {"proxy-authorization", "Basic " <> Base.encode64("user:pass")} ],
            proxy: {:http, ip, port, []},
            transport_opts: [
              # https://hexdocs.pm/mint/Mint.HTTP.html#connect/4-transport-options
              # verify: :verify_none
              verify: :verify_peer,
              cacerts: [download_fiddler_cert_from_fiddler(ip, port)]
              ## openssl x509 -inform der -in FiddlerRoot.cer -out FiddlerRoot.pem
              # cacertfile: Path.join([System.user_home!(), "FiddlerRoot.pem"])
            ]
          ]
        )
    end
  end

  defp download_fiddler_cert_from_fiddler(fiddler_ip, fiddler_port) do
    Application.ensure_all_started([:inets, :ssl])

    # Download the Fiddler MITM certificate
    {:ok, {{_, 200, _}, _, der_binary}} =
      :httpc.request(String.to_charlist("http://#{fiddler_ip}:#{fiddler_port}/FiddlerRoot.cer"))

    der_binary
    |> IO.iodata_to_binary()
  end

  defp fetch_proxy_server_from_windows_registry do
    System.cmd(
      "reg.exe",
      [
        "query",
        "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
        "/v",
        "ProxyServer"
      ],
      stderr_to_stdout: true
    )
    |> case do
      {output, 0} ->
        {port, ""} = extract_port(output)
        {:ok, port}

      {_, 1} ->
        nil
    end
  end

  # defp fetch_proxy_enabled_from_windows_registry do
  #   try do
  #     case System.cmd(
  #            "reg.exe",
  #            [
  #              "query",
  #              "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
  #              "/v",
  #              "ProxyEnable"
  #            ],
  #            stderr_to_stdout: true
  #          ) do
  #       {output, 0} ->
  #         parse_proxy_enable(output)
  #
  #       {error, _} ->
  #         {:error, "Command failed: #{error}"}
  #     end
  #   rescue
  #     e in ErlangError -> {:error, "System command failed: #{inspect(e)}"}
  #   end
  # end
  #
  # defp parse_proxy_enable(output) do
  #   case Regex.run(~r/ProxyEnable\s+REG_DWORD\s+0x([0-9a-fA-F]+)/, output) do
  #     [_, value] ->
  #       case Integer.parse(value, 16) do
  #         {1, _} -> {:ok, true}
  #         {0, _} -> {:ok, false}
  #         _ -> {:error, :unexpected_value}
  #       end
  #
  #     nil ->
  #       {:error, :no_match}
  #   end
  # end

  # @doc"""
  # Extracts the port number from the output of the `reg.exe` command.
  # """
  defp extract_port(output) do
    output
    |> String.trim()
    |> String.split("\r\n")
    |> Enum.at(-1)
    |> (&Regex.run(~r/^\s*ProxyServer\s+REG_SZ\s+http=127.0.0.1:(.*);/, &1)).()
    |> Enum.at(-1)
    |> Integer.parse()
  end

  defp get_address do
    {output, 0} = System.cmd("ipconfig.exe", [])

    output
    |> String.split("\r\n")
    |> Enum.filter(&String.contains?(&1, "IPv4"))
    |> Enum.map(&Regex.run(~r/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/, &1))
  end

  defp proxy_settings_from_registry do
    case fetch_proxy_server_from_windows_registry() do
      {:ok, port} ->
        addr =
          get_address()
          |> List.flatten()
          |> Enum.uniq()
          |> Enum.filter(&String.contains?(&1, "192.168"))
          |> hd

        {:ok, addr, port}

      nil ->
        nil
    end
  end

  @doc """
  Fetches the proxy settings.

  Returns `{:ok, addr, port}` if the proxy server is set.
  Returns `nil` if the proxy server is not set.
  """
  def proxy_settings(opts \\ []) do
    {:ok, opts} = NimbleOptions.validate(opts, @schema)
    {ip, opts} = opts |> Keyword.pop(:ip)
    {port, _opts} = opts |> Keyword.pop(:port)

    case {ip, port} do
      {nil, nil} -> proxy_settings_from_registry()
      {nil, _} -> proxy_settings_from_registry()
      {_, nil} -> proxy_settings_from_registry()
      {ip, port} -> {:ok, ip, port}
    end
  end

  @doc """
  Enables Fiddler as a proxy for `:httpc` globally
  """
  def inject_fiddler_httpc(opts \\ []) do
    {:ok, fiddler_ip, fiddler_port} = proxy_settings(opts)

    cert = download_fiddler_cert_from_fiddler(fiddler_ip, fiddler_port)
    # Convert the certificate to PEM text structure
    pem =
      cert
      |> Base.encode64()
      |> String.replace(~r/.{64}/, "\\0\n")
      |> then(&"-----BEGIN CERTIFICATE-----\n#{&1}\n-----END CERTIFICATE-----")

    # Write to a file (so :public_key.cacerts_load/1 can load from a temporary file)
    temp_file = Path.join(System.tmp_dir(), "fiddler_cert-#{:erlang.unique_integer()}.pem")
    File.write!(temp_file, pem)

    # Replace all trusted root CA certs with a single fake one 🔥
    :ok = :public_key.cacerts_load(temp_file)
    File.rm!(temp_file)

    # Globally have it use the proxy
    :httpc.set_options(proxy: {{String.to_charlist(fiddler_ip), fiddler_port}, []})
  end
end

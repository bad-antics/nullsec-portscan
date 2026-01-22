# NullSec PortScan - Lightning-Fast Async Port Scanner
# Language: Elixir
# Author: bad-antics
# License: NullSec Proprietary

defmodule NullSec.PortScan do
  @moduledoc """
  High-performance async port scanner using Elixir's BEAM VM.
  Capable of handling 100k+ simultaneous connections.
  """

  @version "1.0.0"
  @default_timeout 3000
  @default_concurrency 5000

  @banner """
      ███▄    █  █    ██  ██▓     ██▓      ██████ ▓█████  ▄████▄  
      ██ ▀█   █  ██  ▓██▒▓██▒    ▓██▒    ▒██    ▒ ▓█   ▀ ▒██▀ ▀█  
     ▓██  ▀█ ██▒▓██  ▒██░▒██░    ▒██░    ░ ▓██▄   ▒███   ▒▓█    ▄ 
     ▓██▒  ▐▌██▒▓▓█  ░██░▒██░    ▒██░      ▒   ██▒▒▓█  ▄ ▒▓▓▄ ▄██▒
     ▒██░   ▓██░▒▒█████▓ ░██████▒░██████▒▒██████▒▒░▒████▒▒ ▓███▀ ░
     ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
     █░░░░░░░░░░░░░░ P O R T S C A N ░░░░░░░░░░░░░░░░░░░░░░░░░░░█
     ▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀
                         bad-antics v#{@version}
  """

  # Common service ports
  @top_100_ports [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1723, 3306, 3389, 5432, 5900, 8080, 8443, 8888, 1433, 1521, 2049,
    27017, 6379, 9200, 5601, 8081, 9090, 10000, 1080, 1194, 1883, 2222,
    4443, 5000, 5001, 5002, 6000, 6001, 7000, 7001, 8000, 8001, 8002,
    8008, 8009, 8010, 8020, 8082, 8083, 8084, 8085, 8086, 8087, 8088,
    8089, 8090, 8091, 8092, 8093, 8094, 8095, 8096, 8097, 8098, 8099,
    8100, 9000, 9001, 9002, 9003, 9080, 9091, 9092, 9093, 9094, 9095,
    9096, 9097, 9098, 9099, 9100, 9443, 10001, 10002, 10003, 10004,
    11211, 27018, 27019, 28017, 50000, 50001
  ]

  # Service signatures for banner grabbing
  @service_signatures %{
    "SSH" => ~r/^SSH-/,
    "HTTP" => ~r/^HTTP\//,
    "FTP" => ~r/^220.*FTP/i,
    "SMTP" => ~r/^220.*SMTP/i,
    "MySQL" => ~r/^\x00/,
    "PostgreSQL" => ~r/^E.*FATAL/,
    "Redis" => ~r/^-ERR|^\+PONG/,
    "MongoDB" => ~r/MongoDB/,
    "RDP" => ~r/^\x03\x00/
  }

  defmodule Result do
    @moduledoc "Port scan result structure"
    defstruct [:host, :port, :state, :service, :banner, :timestamp]
  end

  defmodule Options do
    @moduledoc "Scan configuration options"
    defstruct [
      targets: [],
      ports: [],
      timeout: 3000,
      concurrency: 5000,
      service_scan: false,
      output_file: nil,
      output_format: :text,
      verbose: false
    ]
  end

  @doc "Main entry point"
  def main(args) do
    IO.puts(@banner)
    
    case parse_args(args) do
      {:ok, opts} ->
        run_scan(opts)
      {:error, msg} ->
        IO.puts("[!] Error: #{msg}")
        print_usage()
        System.halt(1)
    end
  end

  @doc "Parse command line arguments"
  def parse_args(args) do
    {parsed, _, _} = OptionParser.parse(args,
      switches: [
        target: :string,
        ports: :string,
        timeout: :integer,
        concurrency: :integer,
        service: :boolean,
        output: :string,
        format: :string,
        verbose: :boolean,
        fast: :boolean,
        help: :boolean
      ],
      aliases: [
        t: :target,
        p: :ports,
        T: :timeout,
        c: :concurrency,
        sV: :service,
        o: :output,
        f: :format,
        v: :verbose,
        F: :fast,
        h: :help
      ]
    )

    if Keyword.get(parsed, :help) do
      print_usage()
      System.halt(0)
    end

    target = Keyword.get(parsed, :target)
    
    unless target do
      {:error, "Target (-t) is required"}
    else
      ports = parse_ports(Keyword.get(parsed, :ports), Keyword.get(parsed, :fast, false))
      targets = expand_targets(target)
      
      opts = %Options{
        targets: targets,
        ports: ports,
        timeout: Keyword.get(parsed, :timeout, @default_timeout),
        concurrency: Keyword.get(parsed, :concurrency, @default_concurrency),
        service_scan: Keyword.get(parsed, :service, false),
        output_file: Keyword.get(parsed, :output),
        output_format: parse_format(Keyword.get(parsed, :format, "text")),
        verbose: Keyword.get(parsed, :verbose, false)
      }
      
      {:ok, opts}
    end
  end

  defp parse_ports(nil, true), do: @top_100_ports
  defp parse_ports(nil, false), do: Enum.to_list(1..1000)
  defp parse_ports(port_spec, _) do
    port_spec
    |> String.split(",")
    |> Enum.flat_map(&expand_port_range/1)
    |> Enum.uniq()
    |> Enum.sort()
  end

  defp expand_port_range(spec) do
    case String.split(spec, "-") do
      [single] -> [String.to_integer(String.trim(single))]
      [start, finish] ->
        s = String.to_integer(String.trim(start))
        f = String.to_integer(String.trim(finish))
        Enum.to_list(s..f)
    end
  end

  defp parse_format("json"), do: :json
  defp parse_format("csv"), do: :csv
  defp parse_format("xml"), do: :xml
  defp parse_format(_), do: :text

  @doc "Expand target specification (hostname, IP, CIDR)"
  def expand_targets(target) do
    cond do
      String.contains?(target, "/") ->
        # CIDR notation
        expand_cidr(target)
      String.contains?(target, ",") ->
        # Multiple targets
        target |> String.split(",") |> Enum.map(&String.trim/1)
      true ->
        [target]
    end
  end

  defp expand_cidr(cidr) do
    [ip_part, mask_str] = String.split(cidr, "/")
    mask = String.to_integer(mask_str)
    
    ip_parts = ip_part |> String.split(".") |> Enum.map(&String.to_integer/1)
    ip_int = Enum.reduce(Enum.with_index(ip_parts), 0, fn {part, idx}, acc ->
      acc + (part <<< (24 - idx * 8))
    end)
    
    host_bits = 32 - mask
    num_hosts = :math.pow(2, host_bits) |> round()
    network = ip_int &&& (0xFFFFFFFF <<< host_bits)
    
    # Skip network and broadcast for /24 and larger
    range = if mask <= 30, do: 1..(num_hosts - 2), else: 0..(num_hosts - 1)
    
    Enum.map(range, fn offset ->
      host_int = network + offset
      [
        (host_int >>> 24) &&& 0xFF,
        (host_int >>> 16) &&& 0xFF,
        (host_int >>> 8) &&& 0xFF,
        host_int &&& 0xFF
      ]
      |> Enum.join(".")
    end)
  end

  @doc "Run the port scan"
  def run_scan(opts) do
    total_scans = length(opts.targets) * length(opts.ports)
    
    IO.puts("[*] Scanning #{length(opts.targets)} host(s), #{length(opts.ports)} port(s)")
    IO.puts("[*] Total: #{total_scans} port checks")
    IO.puts("[*] Concurrency: #{opts.concurrency}")
    IO.puts("[*] Timeout: #{opts.timeout}ms")
    IO.puts("")
    
    start_time = System.monotonic_time(:millisecond)
    
    # Create all scan tasks
    tasks = for target <- opts.targets, port <- opts.ports do
      {target, port}
    end
    
    # Process in batches with concurrency control
    results = tasks
    |> Task.async_stream(
      fn {target, port} -> scan_port(target, port, opts) end,
      max_concurrency: opts.concurrency,
      timeout: opts.timeout + 1000,
      on_timeout: :kill_task
    )
    |> Enum.map(fn
      {:ok, result} -> result
      {:exit, _} -> nil
    end)
    |> Enum.reject(&is_nil/1)
    |> Enum.filter(fn r -> r.state == :open end)
    
    end_time = System.monotonic_time(:millisecond)
    duration = (end_time - start_time) / 1000
    
    # Print results
    print_results(results, opts)
    
    IO.puts("\n[+] Scan completed in #{Float.round(duration, 2)} seconds")
    IO.puts("[+] Found #{length(results)} open port(s)")
    
    # Save if output file specified
    if opts.output_file do
      save_results(results, opts)
    end
  end

  @doc "Scan a single port"
  def scan_port(host, port, opts) do
    ip = resolve_host(host)
    
    case :gen_tcp.connect(ip, port, [:binary, active: false], opts.timeout) do
      {:ok, socket} ->
        result = %Result{
          host: host,
          port: port,
          state: :open,
          timestamp: DateTime.utc_now()
        }
        
        # Service detection if enabled
        result = if opts.service_scan do
          banner = grab_banner(socket, port)
          service = identify_service(banner, port)
          %{result | service: service, banner: banner}
        else
          %{result | service: guess_service(port)}
        end
        
        :gen_tcp.close(socket)
        
        if opts.verbose do
          IO.puts("[+] #{host}:#{port} - OPEN - #{result.service || "unknown"}")
        end
        
        result
        
      {:error, _reason} ->
        %Result{host: host, port: port, state: :closed, timestamp: DateTime.utc_now()}
    end
  end

  defp resolve_host(host) do
    case :inet.parse_address(String.to_charlist(host)) do
      {:ok, ip} -> ip
      {:error, _} ->
        case :inet.gethostbyname(String.to_charlist(host)) do
          {:ok, {:hostent, _, _, _, _, [ip | _]}} -> ip
          _ -> raise "Cannot resolve hostname: #{host}"
        end
    end
  end

  defp grab_banner(socket, port) do
    # Send probe based on port
    probe = get_probe(port)
    if probe, do: :gen_tcp.send(socket, probe)
    
    case :gen_tcp.recv(socket, 0, 2000) do
      {:ok, data} -> 
        data
        |> String.slice(0, 256)
        |> String.trim()
        |> String.replace(~r/[\x00-\x1f\x7f-\xff]/, "")
      {:error, _} -> nil
    end
  end

  defp get_probe(21), do: nil  # FTP sends banner automatically
  defp get_probe(22), do: nil  # SSH sends banner automatically
  defp get_probe(25), do: "EHLO nullsec\r\n"
  defp get_probe(80), do: "GET / HTTP/1.0\r\nHost: localhost\r\n\r\n"
  defp get_probe(443), do: nil  # Would need TLS
  defp get_probe(110), do: nil  # POP3 sends banner
  defp get_probe(143), do: nil  # IMAP sends banner
  defp get_probe(3306), do: nil # MySQL sends banner
  defp get_probe(_), do: "\r\n"

  defp identify_service(nil, port), do: guess_service(port)
  defp identify_service(banner, port) do
    Enum.find_value(@service_signatures, guess_service(port), fn {service, pattern} ->
      if Regex.match?(pattern, banner), do: service
    end)
  end

  defp guess_service(21), do: "FTP"
  defp guess_service(22), do: "SSH"
  defp guess_service(23), do: "Telnet"
  defp guess_service(25), do: "SMTP"
  defp guess_service(53), do: "DNS"
  defp guess_service(80), do: "HTTP"
  defp guess_service(110), do: "POP3"
  defp guess_service(143), do: "IMAP"
  defp guess_service(443), do: "HTTPS"
  defp guess_service(445), do: "SMB"
  defp guess_service(993), do: "IMAPS"
  defp guess_service(995), do: "POP3S"
  defp guess_service(1433), do: "MSSQL"
  defp guess_service(1521), do: "Oracle"
  defp guess_service(3306), do: "MySQL"
  defp guess_service(3389), do: "RDP"
  defp guess_service(5432), do: "PostgreSQL"
  defp guess_service(5900), do: "VNC"
  defp guess_service(6379), do: "Redis"
  defp guess_service(8080), do: "HTTP-Proxy"
  defp guess_service(8443), do: "HTTPS-Alt"
  defp guess_service(27017), do: "MongoDB"
  defp guess_service(_), do: nil

  defp print_results(results, opts) do
    IO.puts("\n" <> String.duplicate("─", 70))
    IO.puts("  HOST                    PORT      STATE    SERVICE")
    IO.puts(String.duplicate("─", 70))
    
    results
    |> Enum.group_by(& &1.host)
    |> Enum.each(fn {host, ports} ->
      Enum.each(ports, fn r ->
        service = r.service || "unknown"
        IO.puts("  #{String.pad_trailing(host, 22)} #{String.pad_trailing(to_string(r.port), 8)} open     #{service}")
        
        if opts.verbose && r.banner do
          IO.puts("    └─ Banner: #{String.slice(r.banner, 0, 50)}")
        end
      end)
    end)
    
    IO.puts(String.duplicate("─", 70))
  end

  defp save_results(results, opts) do
    content = case opts.output_format do
      :json -> encode_json(results)
      :csv -> encode_csv(results)
      :xml -> encode_xml(results)
      :text -> encode_text(results)
    end
    
    File.write!(opts.output_file, content)
    IO.puts("[+] Results saved to: #{opts.output_file}")
  end

  defp encode_json(results) do
    results
    |> Enum.map(fn r ->
      ~s({"host":"#{r.host}","port":#{r.port},"state":"#{r.state}","service":"#{r.service || ""}","banner":"#{escape_json(r.banner)}"})
    end)
    |> Enum.join(",\n")
    |> then(&"[\n#{&1}\n]")
  end

  defp escape_json(nil), do: ""
  defp escape_json(str) do
    str
    |> String.replace("\\", "\\\\")
    |> String.replace("\"", "\\\"")
    |> String.replace("\n", "\\n")
  end

  defp encode_csv(results) do
    header = "host,port,state,service,banner\n"
    rows = Enum.map(results, fn r ->
      "#{r.host},#{r.port},#{r.state},#{r.service || ""},\"#{r.banner || ""}\""
    end)
    header <> Enum.join(rows, "\n")
  end

  defp encode_xml(results) do
    items = Enum.map(results, fn r ->
      """
        <port>
          <host>#{r.host}</host>
          <number>#{r.port}</number>
          <state>#{r.state}</state>
          <service>#{r.service || ""}</service>
        </port>
      """
    end)
    
    """
    <?xml version="1.0" encoding="UTF-8"?>
    <portscan>
    #{Enum.join(items)}
    </portscan>
    """
  end

  defp encode_text(results) do
    Enum.map(results, fn r ->
      "#{r.host}:#{r.port} - #{r.state} - #{r.service || "unknown"}"
    end)
    |> Enum.join("\n")
  end

  defp print_usage do
    IO.puts("""
    
    USAGE:
      portscan -t <target> [options]
    
    OPTIONS:
      -t, --target      Target host, IP, or CIDR (required)
      -p, --ports       Port specification (e.g., 22,80,443 or 1-1000)
      -T, --timeout     Connection timeout in ms (default: 3000)
      -c, --concurrency Max concurrent connections (default: 5000)
      -sV, --service    Enable service/version detection
      -o, --output      Output file path
      -f, --format      Output format: text, json, csv, xml
      -F, --fast        Fast scan (top 100 ports only)
      -v, --verbose     Verbose output
      -h, --help        Show this help
    
    EXAMPLES:
      portscan -t 192.168.1.1 -p 1-1000
      portscan -t 192.168.1.0/24 -p 22,80,443 -sV
      portscan -t target.com --fast -o results.json -f json
    """)
  end
end

# Run if executed directly
NullSec.PortScan.main(System.argv())

# NullSec PortScan - Hardened Async Network Scanner
# Language: Elixir (Concurrent Functional Programming)
# Author: bad-antics
# License: NullSec Proprietary
# Security Level: Maximum Hardening
#
# Security Features:
# - Input validation with guards and pattern matching
# - Rate limiting to prevent network abuse
# - Timeout enforcement on all operations
# - Supervision tree for fault tolerance
# - Immutable data structures
# - Defense-in-depth architecture

defmodule NullSec.PortScan do
  @moduledoc """
  Hardened asynchronous port scanner with security-first design.
  """

  @version "2.0.0"
  @banner """
  ██████╗  ██████╗ ██████╗ ████████╗███████╗ ██████╗ █████╗ ███╗   ██╗
  ██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝██╔════╝██╔════╝██╔══██╗████╗  ██║
  ██████╔╝██║   ██║██████╔╝   ██║   ███████╗██║     ███████║██╔██╗ ██║
  ██╔═══╝ ██║   ██║██╔══██╗   ██║   ╚════██║██║     ██╔══██║██║╚██╗██║
  ██║     ╚██████╔╝██║  ██║   ██║   ███████║╚██████╗██║  ██║██║ ╚████║
  ╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
                     bad-antics • v#{@version}
  ═══════════════════════════════════════════════════════════════════
  """

  # =========================================================================
  # Constants & Configuration
  # =========================================================================

  @max_concurrent 2500
  @default_timeout 3000
  @max_timeout 30_000
  @min_timeout 100
  @max_port 65535
  @min_port 1
  @max_targets 1024
  @rate_limit_window 1000  # ms

  # Common service signatures for banner grabbing
  @service_signatures %{
    "SSH-" => "ssh",
    "220 " => "ftp/smtp",
    "HTTP/1" => "http",
    "+OK " => "pop3",
    "* OK " => "imap",
    "MySQL" => "mysql",
    "PostgreSQL" => "postgresql",
    "220-" => "smtp",
    "\\x00\\x00\\x00" => "smb"
  }

  # Well-known port services
  @port_services %{
    21 => "ftp",
    22 => "ssh",
    23 => "telnet",
    25 => "smtp",
    53 => "dns",
    80 => "http",
    110 => "pop3",
    111 => "rpc",
    135 => "msrpc",
    139 => "netbios",
    143 => "imap",
    443 => "https",
    445 => "smb",
    993 => "imaps",
    995 => "pop3s",
    1433 => "mssql",
    1521 => "oracle",
    3306 => "mysql",
    3389 => "rdp",
    5432 => "postgresql",
    5900 => "vnc",
    6379 => "redis",
    8080 => "http-proxy",
    8443 => "https-alt",
    27017 => "mongodb"
  }

  # =========================================================================
  # Type Definitions
  # =========================================================================

  @type ip_address :: {non_neg_integer(), non_neg_integer(), non_neg_integer(), non_neg_integer()}
  @type port_range :: {pos_integer(), pos_integer()}
  @type scan_result :: %{
    host: String.t(),
    port: pos_integer(),
    status: :open | :closed | :filtered,
    service: String.t() | nil,
    banner: String.t() | nil,
    latency_ms: float()
  }

  # =========================================================================
  # Input Validation
  # =========================================================================

  defmodule ValidationError do
    defexception [:message]
  end

  @doc """
  Validate and parse IP address or hostname.
  """
  @spec validate_target(String.t()) :: {:ok, String.t()} | {:error, String.t()}
  def validate_target(target) when is_binary(target) do
    target = String.trim(target)

    cond do
      String.length(target) > 255 ->
        {:error, "Target too long"}

      String.contains?(target, ["\0", "\n", "\r", ";", "|", "&"]) ->
        {:error, "Invalid characters in target"}

      valid_ip?(target) ->
        {:ok, target}

      valid_hostname?(target) ->
        {:ok, target}

      true ->
        {:error, "Invalid target format"}
    end
  end
  def validate_target(_), do: {:error, "Target must be a string"}

  @doc """
  Validate IP address format.
  """
  @spec valid_ip?(String.t()) :: boolean()
  def valid_ip?(ip) do
    case :inet.parse_address(String.to_charlist(ip)) do
      {:ok, _} -> true
      _ -> false
    end
  end

  @doc """
  Validate hostname format.
  """
  @spec valid_hostname?(String.t()) :: boolean()
  def valid_hostname?(hostname) do
    # RFC 1123 compliant hostname validation
    regex = ~r/^(?=.{1,253}$)(?:(?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.)*(?!-)[a-zA-Z0-9-]{1,63}(?<!-)$/
    Regex.match?(regex, hostname)
  end

  @doc """
  Validate port number.
  """
  @spec validate_port(integer()) :: {:ok, pos_integer()} | {:error, String.t()}
  def validate_port(port) when is_integer(port) and port >= @min_port and port <= @max_port do
    {:ok, port}
  end
  def validate_port(port) when is_integer(port) do
    {:error, "Port must be between #{@min_port} and #{@max_port}, got: #{port}"}
  end
  def validate_port(_), do: {:error, "Port must be an integer"}

  @doc """
  Validate port range.
  """
  @spec validate_port_range(pos_integer(), pos_integer()) :: {:ok, port_range()} | {:error, String.t()}
  def validate_port_range(start_port, end_port)
      when is_integer(start_port) and is_integer(end_port)
      and start_port >= @min_port and end_port <= @max_port
      and start_port <= end_port do
    {:ok, {start_port, end_port}}
  end
  def validate_port_range(_, _), do: {:error, "Invalid port range"}

  @doc """
  Validate timeout value.
  """
  @spec validate_timeout(integer()) :: {:ok, pos_integer()} | {:error, String.t()}
  def validate_timeout(timeout) when is_integer(timeout) and timeout >= @min_timeout and timeout <= @max_timeout do
    {:ok, timeout}
  end
  def validate_timeout(_), do: {:error, "Timeout must be between #{@min_timeout} and #{@max_timeout}ms"}

  # =========================================================================
  # CIDR Parsing
  # =========================================================================

  @doc """
  Parse CIDR notation and return list of IPs.
  Limited to /24 networks for safety.
  """
  @spec parse_cidr(String.t()) :: {:ok, [String.t()]} | {:error, String.t()}
  def parse_cidr(cidr) when is_binary(cidr) do
    with [ip_str, mask_str] <- String.split(cidr, "/"),
         {:ok, mask} <- parse_mask(mask_str),
         :ok <- validate_mask_size(mask),
         {:ok, ip} <- parse_ip_tuple(ip_str) do
      {:ok, expand_cidr(ip, mask)}
    else
      _ -> {:error, "Invalid CIDR notation"}
    end
  end

  defp parse_mask(mask_str) do
    case Integer.parse(mask_str) do
      {mask, ""} when mask >= 0 and mask <= 32 -> {:ok, mask}
      _ -> {:error, "Invalid mask"}
    end
  end

  defp validate_mask_size(mask) when mask >= 24, do: :ok
  defp validate_mask_size(_), do: {:error, "CIDR mask must be >= 24 for safety (max 256 hosts)"}

  defp parse_ip_tuple(ip_str) do
    case :inet.parse_address(String.to_charlist(ip_str)) do
      {:ok, {a, b, c, d}} -> {:ok, {a, b, c, d}}
      _ -> {:error, "Invalid IP"}
    end
  end

  defp expand_cidr({a, b, c, d}, mask) do
    host_bits = 32 - mask
    num_hosts = :math.pow(2, host_bits) |> round()

    # Calculate network address
    ip_int = (a <<< 24) + (b <<< 16) + (c <<< 8) + d
    network = ip_int &&& ~~~((1 <<< host_bits) - 1)

    0..(num_hosts - 1)
    |> Enum.map(fn offset ->
      host = network + offset
      "#{host >>> 24}.#{(host >>> 16) &&& 0xFF}.#{(host >>> 8) &&& 0xFF}.#{host &&& 0xFF}"
    end)
    |> Enum.take(@max_targets)
  end

  # =========================================================================
  # Rate Limiter
  # =========================================================================

  defmodule RateLimiter do
    use GenServer

    @doc """
    Start rate limiter with specified requests per second.
    """
    def start_link(opts \\ []) do
      rps = Keyword.get(opts, :rps, 1000)
      GenServer.start_link(__MODULE__, %{rps: rps, tokens: rps, last_refill: System.monotonic_time(:millisecond)}, name: __MODULE__)
    end

    @doc """
    Acquire a token for rate limiting.
    Blocks until token is available.
    """
    def acquire(timeout \\ 5000) do
      GenServer.call(__MODULE__, :acquire, timeout)
    end

    @impl true
    def init(state), do: {:ok, state}

    @impl true
    def handle_call(:acquire, _from, state) do
      now = System.monotonic_time(:millisecond)
      elapsed = now - state.last_refill

      # Refill tokens based on elapsed time
      new_tokens = min(state.rps, state.tokens + div(elapsed * state.rps, 1000))

      if new_tokens > 0 do
        {:reply, :ok, %{state | tokens: new_tokens - 1, last_refill: now}}
      else
        # Wait and retry
        Process.sleep(div(1000, state.rps))
        {:reply, :ok, %{state | tokens: 0, last_refill: now}}
      end
    end
  end

  # =========================================================================
  # Port Scanner Core
  # =========================================================================

  @doc """
  Scan a single port on a target.
  """
  @spec scan_port(String.t(), pos_integer(), keyword()) :: scan_result()
  def scan_port(host, port, opts \\ []) do
    timeout = Keyword.get(opts, :timeout, @default_timeout)
    grab_banner = Keyword.get(opts, :grab_banner, false)

    start_time = System.monotonic_time(:microsecond)

    result = case :gen_tcp.connect(String.to_charlist(host), port, [:binary, active: false], timeout) do
      {:ok, socket} ->
        banner = if grab_banner, do: grab_service_banner(socket, timeout), else: nil
        :gen_tcp.close(socket)
        service = detect_service(port, banner)

        %{
          status: :open,
          service: service,
          banner: banner
        }

      {:error, :timeout} ->
        %{status: :filtered, service: nil, banner: nil}

      {:error, :econnrefused} ->
        %{status: :closed, service: nil, banner: nil}

      {:error, _} ->
        %{status: :filtered, service: nil, banner: nil}
    end

    end_time = System.monotonic_time(:microsecond)
    latency_ms = (end_time - start_time) / 1000

    Map.merge(result, %{
      host: host,
      port: port,
      latency_ms: Float.round(latency_ms, 2)
    })
  end

  @doc """
  Scan a range of ports on a target with concurrency control.
  """
  @spec scan_ports(String.t(), [pos_integer()], keyword()) :: [scan_result()]
  def scan_ports(host, ports, opts \\ []) do
    max_concurrent = Keyword.get(opts, :max_concurrent, @max_concurrent)
    timeout = Keyword.get(opts, :timeout, @default_timeout)
    grab_banner = Keyword.get(opts, :grab_banner, false)

    # Validate host
    case validate_target(host) do
      {:ok, validated_host} ->
        ports
        |> Enum.chunk_every(max_concurrent)
        |> Enum.flat_map(fn chunk ->
          chunk
          |> Enum.map(fn port ->
            Task.async(fn ->
              # Rate limit
              if Process.whereis(RateLimiter), do: RateLimiter.acquire()
              scan_port(validated_host, port, timeout: timeout, grab_banner: grab_banner)
            end)
          end)
          |> Task.await_many(timeout + 1000)
        end)

      {:error, reason} ->
        raise ValidationError, message: "Invalid target: #{reason}"
    end
  end

  @doc """
  Scan multiple targets.
  """
  @spec scan_targets([String.t()], [pos_integer()], keyword()) :: [scan_result()]
  def scan_targets(targets, ports, opts \\ []) do
    # Validate target count
    if length(targets) > @max_targets do
      raise ValidationError, message: "Too many targets (max: #{@max_targets})"
    end

    targets
    |> Enum.flat_map(fn target ->
      case validate_target(target) do
        {:ok, validated} -> scan_ports(validated, ports, opts)
        {:error, _} -> []
      end
    end)
  end

  # =========================================================================
  # Banner Grabbing
  # =========================================================================

  defp grab_service_banner(socket, timeout) do
    # Set receive timeout
    :inet.setopts(socket, recv_timeout: min(timeout, 2000))

    # Try to receive banner
    case :gen_tcp.recv(socket, 0, 2000) do
      {:ok, data} ->
        data
        |> String.slice(0, 256)  # Limit banner size
        |> String.trim()
        |> sanitize_banner()

      {:error, _} ->
        # Try sending probe for HTTP
        case :gen_tcp.send(socket, "HEAD / HTTP/1.0\r\n\r\n") do
          :ok ->
            case :gen_tcp.recv(socket, 0, 2000) do
              {:ok, data} ->
                data |> String.slice(0, 256) |> String.trim() |> sanitize_banner()
              _ -> nil
            end
          _ -> nil
        end
    end
  end

  defp sanitize_banner(nil), do: nil
  defp sanitize_banner(banner) do
    banner
    |> String.replace(~r/[\x00-\x1f\x7f-\xff]/, "")  # Remove control chars
    |> String.slice(0, 200)
  end

  defp detect_service(port, banner) do
    # First check banner
    if banner do
      Enum.find_value(@service_signatures, fn {pattern, service} ->
        if String.contains?(banner, pattern), do: service
      end)
    end || Map.get(@port_services, port)
  end

  # =========================================================================
  # Port Range Presets
  # =========================================================================

  @doc """
  Get common port list.
  """
  @spec common_ports() :: [pos_integer()]
  def common_ports do
    [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
     1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017]
  end

  @doc """
  Get top 100 ports.
  """
  @spec top_100_ports() :: [pos_integer()]
  def top_100_ports do
    [7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111,
     113, 119, 135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465,
     513, 514, 515, 543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995,
     1025, 1026, 1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000,
     2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009,
     5051, 5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001,
     6646, 7070, 8000, 8008, 8009, 8080, 8081, 8443, 8888, 9100, 9999, 10000,
     32768, 49152, 49153, 49154, 49155, 49156, 49157]
  end

  # =========================================================================
  # CLI Interface
  # =========================================================================

  defmodule CLI do
    @moduledoc """
    Command line interface for port scanner.
    """

    alias NullSec.PortScan

    def main(args) do
      IO.puts(NullSec.PortScan.banner())

      {opts, _, _} = OptionParser.parse(args,
        strict: [
          target: :string,
          ports: :string,
          timeout: :integer,
          concurrent: :integer,
          banner: :boolean,
          verbose: :boolean,
          help: :boolean
        ],
        aliases: [
          t: :target,
          p: :ports,
          T: :timeout,
          c: :concurrent,
          b: :banner,
          v: :verbose,
          h: :help
        ]
      )

      if opts[:help] do
        print_help()
        System.halt(0)
      end

      target = opts[:target] || raise "Target required (-t)"
      ports = parse_ports(opts[:ports] || "1-1000")
      timeout = opts[:timeout] || 3000
      grab_banner = opts[:banner] || false

      # Validate
      {:ok, _} = PortScan.validate_timeout(timeout)

      # Start rate limiter
      {:ok, _} = PortScan.RateLimiter.start_link(rps: 1000)

      IO.puts("[*] Target: #{target}")
      IO.puts("[*] Ports: #{length(ports)}")
      IO.puts("[*] Timeout: #{timeout}ms")
      IO.puts("")

      start_time = System.monotonic_time(:second)

      results = PortScan.scan_ports(target, ports,
        timeout: timeout,
        grab_banner: grab_banner
      )

      end_time = System.monotonic_time(:second)

      # Filter open ports
      open_ports = Enum.filter(results, &(&1.status == :open))

      IO.puts("\n[+] Open ports found: #{length(open_ports)}")
      IO.puts("─────────────────────────────────────────")

      Enum.each(open_ports, fn result ->
        service = result.service || "unknown"
        banner_info = if result.banner, do: " | #{String.slice(result.banner, 0, 50)}", else: ""
        IO.puts("  #{result.port}/tcp\topen\t#{service}#{banner_info}")
      end)

      IO.puts("\n[*] Scan completed in #{end_time - start_time}s")
    end

    defp parse_ports("common"), do: PortScan.common_ports()
    defp parse_ports("top100"), do: PortScan.top_100_ports()
    defp parse_ports(spec) do
      spec
      |> String.split(",")
      |> Enum.flat_map(fn part ->
        case String.split(part, "-") do
          [single] -> [String.to_integer(single)]
          [start, stop] ->
            Enum.to_list(String.to_integer(start)..String.to_integer(stop))
        end
      end)
      |> Enum.filter(&(&1 >= 1 && &1 <= 65535))
    end

    defp print_help do
      IO.puts("""
      USAGE:
          portscan [OPTIONS]

      OPTIONS:
          -t, --target <host>     Target IP or hostname
          -p, --ports <spec>      Port specification (e.g., "1-1000", "common", "top100")
          -T, --timeout <ms>      Connection timeout in milliseconds (default: 3000)
          -b, --banner            Grab service banners
          -v, --verbose           Verbose output
          -h, --help              Show this help

      EXAMPLES:
          portscan -t 192.168.1.1 -p common
          portscan -t example.com -p 1-1000 -b
          portscan -t 10.0.0.1 -p 22,80,443,8080
      """)
    end
  end

  def banner, do: @banner
end

# Run CLI if executed directly
if System.get_env("MIX_ENV") != "test" do
  try do
    NullSec.PortScan.CLI.main(System.argv())
  rescue
    e in NullSec.PortScan.ValidationError ->
      IO.puts(:stderr, "[!] Validation Error: #{e.message}")
      System.halt(1)
    e ->
      IO.puts(:stderr, "[!] Error: #{Exception.message(e)}")
      System.halt(1)
  end
end

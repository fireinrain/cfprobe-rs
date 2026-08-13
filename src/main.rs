use std::error::Error;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use clap::{Args, Parser, Subcommand, ValueEnum};

use futures::StreamExt;

use tracing::info;

use tracing_subscriber::{
    filter::{EnvFilter, LevelFilter},
    fmt,
};

use cfprobe::{BatchScanConfig, CfProbe, CfProbeConfig, HttpScheme, ServerConfig, Target};

#[derive(Debug, Parser)]
#[command(
    name = "cfprobe",
    version,
    about = "Cloudflare CDN reverse-proxy detection engine",
    long_about = None,
)]
struct Cli {
    /// Enable JSON structured logging.
    #[arg(long, global = true)]
    json_logs: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Detect one IP + hostname.
    Check(CheckArgs),

    /// Scan targets from a text file.
    Batch(BatchArgs),

    /// Start the HTTP API server.
    Serve(ServeArgs),
}

#[derive(Debug, Args)]
struct CheckArgs {
    /// Target IP address.
    #[arg(long)]
    ip: IpAddr,

    /// Target hostname.
    #[arg(long)]
    host: String,

    /// Target port.
    #[arg(long, default_value_t = 443)]
    port: u16,

    /// Protocol scheme.
    #[arg(
        long,
        value_enum,
        default_value_t = CliScheme::Https,
    )]
    scheme: CliScheme,

    /// Output the full JSON result.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct BatchArgs {
    /// Input target file.
    ///
    /// Each non-empty line should use:
    ///
    /// IP HOST
    /// IP HOST PORT
    /// IP HOST PORT SCHEME
    ///
    /// Example:
    ///
    /// 104.16.77.250 example.com
    /// 104.16.77.250 example.com 443 https
    #[arg(long, value_name = "FILE")]
    file: PathBuf,

    /// Maximum number of targets running concurrently.
    #[arg(long, default_value_t = 32)]
    concurrency: usize,

    /// Maximum execution time of one target in milliseconds.
    #[arg(long, default_value_t = 30_000)]
    timeout_ms: u64,

    /// Maximum number of new targets started per second.
    #[arg(long)]
    rps: Option<u32>,

    /// Maximum number of targets accepted from the input file.
    #[arg(long, default_value_t = 10_000)]
    max_targets: usize,

    /// Emit the complete batch result as JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct ServeArgs {
    /// Bind address.
    #[arg(long, default_value = "127.0.0.1:8080")]
    listen: SocketAddr,

    /// Bearer token / API key.
    ///
    /// May also be supplied using:
    ///
    /// CFPROBE_API_KEY
    #[arg(long, env = "CFPROBE_API_KEY")]
    api_key: Option<String>,

    /// Maximum HTTP request body in bytes.
    #[arg(
        long,
        default_value_t = 1024 * 1024,
    )]
    max_body_bytes: usize,

    /// Maximum number of targets in one /v1/scan request.
    #[arg(long, default_value_t = 1000)]
    max_batch_targets: usize,

    /// Default batch concurrency.
    #[arg(long, default_value_t = 32)]
    concurrency: usize,

    /// Default target timeout in milliseconds.
    #[arg(long, default_value_t = 30_000)]
    timeout_ms: u64,

    /// Default maximum number of new targets started per second.
    #[arg(long)]
    rps: Option<u32>,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CliScheme {
    Http,
    Https,
}

impl From<CliScheme> for HttpScheme {
    fn from(value: CliScheme) -> Self {
        match value {
            CliScheme::Http => HttpScheme::Http,

            CliScheme::Https => HttpScheme::Https,
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    cfprobe::init_rustls_crypto();

    let cli = Cli::parse();

    init_tracing(cli.json_logs);

    match cli.command {
        Commands::Check(args) => {
            run_check(args).await?;
        }

        Commands::Batch(args) => {
            run_batch(args).await?;
        }

        Commands::Serve(args) => {
            run_server(args).await?;
        }
    }

    Ok(())
}

fn init_tracing(json: bool) {
    let filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .from_env_lossy();

    if json {
        fmt().json().with_env_filter(filter).init();
    } else {
        fmt().with_env_filter(filter).init();
    }
}

async fn build_probe() -> Result<CfProbe, Box<dyn Error>> {
    let config = CfProbeConfig::cloudflare_web_proxy_v1()?;

    let probe = CfProbe::new(config).await?;

    Ok(probe)
}

async fn run_check(args: CheckArgs) -> Result<(), Box<dyn Error>> {
    let target = Target {
        ip: args.ip,

        hostname: args.host,

        port: args.port,

        scheme: args.scheme.into(),
    };

    target.validate()?;

    info!(
        ip = %target.ip,
        hostname = %target.hostname,
        port = target.port,
        scheme = ?target.scheme,
        "starting single target probe",
    );

    let probe = build_probe().await?;

    let result = probe.detect(target).await?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&result,)?,);

        return Ok(());
    }

    println!("classification: {:?}", result.detection.classification,);

    println!("confidence: {:.2}", result.detection.confidence,);

    println!("confidence level: {:?}", result.detection.confidence_level,);

    println!("score: {}", result.detection.score,);

    println!(
        "policy: {} v{}",
        result.detection.policy.name, result.detection.policy.version,
    );

    println!("summary: {}", result.detection.summary,);

    if !result.errors.is_empty() {
        println!();
        println!("stage errors:",);

        for error in &result.errors {
            println!("- {:?}: {}", error.stage, error.message,);
        }
    }

    Ok(())
}

async fn run_batch(args: BatchArgs) -> Result<(), Box<dyn Error>> {
    let targets = load_targets(&args.file)?;

    if targets.is_empty() {
        return Err(format!("no valid targets found in {}", args.file.display(),).into());
    }

    if targets.len() > args.max_targets {
        return Err(format!(
            "input contains {} targets, exceeding --max-targets {}",
            targets.len(),
            args.max_targets,
        )
        .into());
    }

    info!(
        count = targets.len(),
        file = %args.file.display(),
        "loaded batch targets",
    );

    let probe = build_probe().await?;

    let config = BatchScanConfig::default()
        .with_concurrency(args.concurrency)
        .with_target_timeout(Duration::from_millis(args.timeout_ms))
        .with_requests_per_second(args.rps)
        .with_max_targets(Some(args.max_targets));

    config.validate()?;

    if args.json {
        let result = probe.scan(targets, config).await?;

        println!("{}", serde_json::to_string_pretty(&result,)?,);

        return Ok(());
    }

    let total = targets.len();

    let mut completed = 0usize;

    let mut stream = probe.scan_unordered(targets, config)?;

    while let Some(item) = stream.next().await {
        completed += 1;

        let classification = item
            .result
            .as_ref()
            .map(|result| result.detection.classification);

        println!(
            "[{}/{}] index={} status={:?} classification={:?} ip={} host={}",
            completed,
            total,
            item.index,
            item.status,
            classification,
            item.target.ip,
            item.target.hostname,
        );

        if let Some(result) = item.result {
            println!(
                "    score={} confidence={:.2}",
                result.detection.score, result.detection.confidence,
            );
        }

        if let Some(error) = item.error {
            println!("    error={}", error,);
        }
    }

    Ok(())
}

async fn run_server(args: ServeArgs) -> Result<(), Box<dyn Error>> {
    let config = ServerConfig {
        listen: args.listen,

        api_key: args.api_key,

        max_body_bytes: args.max_body_bytes,

        max_batch_targets: args.max_batch_targets,

        default_concurrency: args.concurrency,

        default_target_timeout_ms: args.timeout_ms,

        default_requests_per_second: args.rps,
    };

    config
        .validate()
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error))?;

    info!(
        listen = %config.listen,
        max_body_bytes =
            config.max_body_bytes,
        max_batch_targets =
            config.max_batch_targets,
        concurrency =
            config.default_concurrency,
        timeout_ms =
            config.default_target_timeout_ms,
        "starting cfprobe server",
    );

    let probe = build_probe().await?;

    cfprobe::server::serve(probe, config).await?;

    Ok(())
}

fn load_targets(path: &Path) -> Result<Vec<Target>, Box<dyn Error>> {
    let content = std::fs::read_to_string(path)?;

    let mut targets = Vec::new();

    for (line_number, line) in content.lines().enumerate() {
        let line = line.trim();

        /*
         * 空行和注释行直接跳过。
         */
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let parts = line.split_whitespace().collect::<Vec<_>>();

        if parts.len() < 2 || parts.len() > 4 {
            return Err(format!(
                "invalid target at {}:{}; expected `IP HOST [PORT] [SCHEME]`",
                path.display(),
                line_number + 1,
            )
            .into());
        }

        let ip: IpAddr = parts[0].parse().map_err(|error| {
            format!(
                "invalid IP `{}` at {}:{}: {}",
                parts[0],
                path.display(),
                line_number + 1,
                error,
            )
        })?;

        let hostname = parts[1].to_string();

        let port = if parts.len() >= 3 {
            parts[2].parse::<u16>().map_err(|error| {
                format!(
                    "invalid port `{}` at {}:{}: {}",
                    parts[2],
                    path.display(),
                    line_number + 1,
                    error,
                )
            })?
        } else {
            443
        };

        if port == 0 {
            return Err(
                format!("invalid port 0 at {}:{}", path.display(), line_number + 1,).into(),
            );
        }

        let scheme = if parts.len() == 4 {
            match parts[3].to_ascii_lowercase().as_str() {
                "http" => HttpScheme::Http,

                "https" => HttpScheme::Https,

                other => {
                    return Err(format!(
                        "invalid scheme `{other}` at {}:{}; expected `http` or `https`",
                        path.display(),
                        line_number + 1,
                    )
                    .into());
                }
            }
        } else if port == 80 {
            HttpScheme::Http
        } else {
            HttpScheme::Https
        };

        let target = Target {
            ip,

            hostname,

            port,

            scheme,
        };

        target.validate().map_err(|error| {
            format!(
                "invalid target at {}:{}: {}",
                path.display(),
                line_number + 1,
                error,
            )
        })?;

        targets.push(target);
    }

    Ok(targets)
}
use anyhow::{Context, Result};
use clap::ValueEnum;
use std::io::Read;
use std::io::Cursor;
use std::path::Path;
use tokio::io::AsyncWriteExt;
use tonic::metadata::MetadataValue;
use tonic::{Request, Status};
use tonic::transport::Channel;

use crate::cli;
use crate::grpc::packetrecorder::packet_recorder_client::PacketRecorderClient;
use crate::grpc::packetrecorder::*;

#[derive(Clone, Debug, ValueEnum)]
pub enum InspectPayloadMode {
    None,
    Ascii,
    Hex,
}

#[derive(Clone)]
struct ApiKeyInterceptor {
    key: MetadataValue<tonic::metadata::Ascii>,
}

impl tonic::service::Interceptor for ApiKeyInterceptor {
    fn call(&mut self, mut req: Request<()>) -> std::result::Result<Request<()>, Status> {
        req.metadata_mut().insert("x-api-key", self.key.clone());
        Ok(req)
    }
}

fn normalize_endpoint(ep: &str) -> String {
    let e = ep.trim();
    if e.starts_with("http://") || e.starts_with("https://") {
        e.to_string()
    } else {
        format!("http://{}", e)
    }
}

fn api_key_from_args(args: &cli::ManageArgs) -> Result<String> {
    if let Some(k) = args.api_key.as_ref() {
        let t = k.trim();
        if !t.is_empty() {
            return Ok(t.to_string());
        }
    }

    if let Ok(k) = std::env::var("PACKETRECORDER_API_KEY") {
        let t = k.trim();
        if !t.is_empty() {
            return Ok(t.to_string());
        }
    }

    anyhow::bail!("missing api key (set --api-key or PACKETRECORDER_API_KEY)")
}

async fn client(
    args: &cli::ManageArgs,
) -> Result<PacketRecorderClient<tonic::service::interceptor::InterceptedService<Channel, ApiKeyInterceptor>>> {
    let endpoint = normalize_endpoint(&args.endpoint);
    let key = api_key_from_args(args)?;

    let channel = Channel::from_shared(endpoint)
        .context("invalid endpoint")?
        .connect()
        .await
        .context("failed to connect")?;

    let mv = MetadataValue::try_from(key.as_str())
        .map_err(|_| Status::internal("invalid api key"))?;

    let interceptor = ApiKeyInterceptor { key: mv };
    Ok(PacketRecorderClient::with_interceptor(channel, interceptor))
}

pub async fn cmd_manage(args: cli::ManageArgs) -> Result<()> {
    match args.command {
        cli::ManageCommands::InspectPcap(cmd) => {
            return inspect_pcap(
                &cmd.path,
                cmd.limit,
                cmd.payload,
                cmd.mime,
                cmd.gzip_decode,
                cmd.zip_decode,
            );
        }
        _ => {}
    }

    let mut c = client(&args).await?;

    match args.command {
        cli::ManageCommands::ListInterfaces(_) => {
            let resp = c
                .list_interfaces(ListInterfacesRequest {})
                .await
                .context("ListInterfaces RPC failed")?
                .into_inner();

            for iface in resp.interfaces {
                println!("{}\t{}\t{}", iface.name, iface.description, iface.addresses.join(","));
            }
        }
        cli::ManageCommands::StartCapture(cmd) => {
            let req = StartCaptureRequest {
                interface: cmd.interface,
                filter: cmd.filter.unwrap_or_default(),
                database_path: "".to_string(),
                max_packets: cmd.max_packets,
                max_duration_seconds: cmd.max_duration_seconds,
                snaplen: cmd.snaplen,
                promisc: cmd.promisc,
                buffer_size: cmd.buffer_size,
            };

            let resp = c
                .start_capture(req)
                .await
                .context("StartCapture RPC failed")?
                .into_inner();

            println!("{}", resp.session_id);
        }
        cli::ManageCommands::StopCapture(cmd) => {
            let resp = c
                .stop_capture(StopCaptureRequest {
                    session_id: cmd.session_id,
                })
                .await
                .context("StopCapture RPC failed")?
                .into_inner();

            println!("{}", resp.stopped);
        }
        cli::ManageCommands::Sessions(_) => {
            let resp = c
                .list_sessions(ListSessionsRequest {
                    database_path: "".to_string(),
                })
                .await
                .context("ListSessions RPC failed")?
                .into_inner();

            for s in resp.sessions {
                println!(
                    "{}\t{}\t{}\t{}\t{}\t{}",
                    s.id,
                    s.interface,
                    s.filter,
                    s.start_time_rfc3339,
                    s.end_time_rfc3339,
                    s.packet_count
                );
            }
        }
        cli::ManageCommands::GetSession(cmd) => {
            let resp = c
                .get_session(GetSessionRequest {
                    session_id: cmd.session_id,
                    database_path: "".to_string(),
                })
                .await
                .context("GetSession RPC failed")?
                .into_inner();

            let Some(s) = resp.session else {
                anyhow::bail!("session not found");
            };

            println!("id: {}", s.id);
            println!("interface: {}", s.interface);
            println!("filter: {}", s.filter);
            println!("start: {}", s.start_time_rfc3339);
            println!("end: {}", s.end_time_rfc3339);
            println!("packet_count: {}", s.packet_count);
        }
        cli::ManageCommands::DownloadPcap(cmd) => {
            let mut stream = c
                .download_pcap(DownloadPcapRequest {
                    session_id: cmd.session_id,
                    database_path: "".to_string(),
                    limit_packets: cmd.limit_packets,
                })
                .await
                .context("DownloadPcap RPC failed")?
                .into_inner();

            let mut file = tokio::fs::File::create(&cmd.output)
                .await
                .with_context(|| format!("failed to create output: {}", cmd.output.display()))?;

            let mut total = 0usize;
            while let Some(msg) = stream.message().await? {
                total += msg.chunk.len();
                file.write_all(&msg.chunk).await?;
            }
            file.flush().await?;

            eprintln!("wrote {} bytes", total);
        }
        cli::ManageCommands::LookupAttribution(cmd) => {
            let proto = match cmd.proto.as_str() {
                "tcp" => IpProto::Tcp as i32,
                "udp" => IpProto::Udp as i32,
                _ => anyhow::bail!("proto must be tcp|udp"),
            };

            let resp = c
                .lookup_attribution(LookupAttributionRequest {
                    flow: Some(FlowTuple {
                        proto,
                        src_ip: cmd.src_ip,
                        src_port: cmd.src_port as u32,
                        dst_ip: cmd.dst_ip,
                        dst_port: cmd.dst_port as u32,
                    }),
                })
                .await
                .context("LookupAttribution RPC failed")?
                .into_inner();

            if !resp.found {
                println!("not found");
                return Ok(());
            }

            let Some(a) = resp.attribution else {
                println!("not found");
                return Ok(());
            };

            println!("pid: {}", a.pid);
            println!("uid: {}", a.uid);
            println!("process: {}", a.process);
            println!("bundle_id: {}", a.bundle_id);
            println!("signing_id: {}", a.signing_id);
            println!("ts: {}", a.timestamp_rfc3339);
        }
        cli::ManageCommands::Keys(cmd) => match cmd.command {
            cli::ManageKeysCommand::List(_) => {
                let resp = c
                    .list_api_keys(ListApiKeysRequest {})
                    .await
                    .context("ListApiKeys RPC failed")?
                    .into_inner();

                for k in resp.keys {
                    println!("{}\t{}", k.sha256_prefix, k.source);
                }
            }
            cli::ManageKeysCommand::Add(a) => {
                let resp = c
                    .add_api_key(AddApiKeyRequest { key: a.key })
                    .await
                    .context("AddApiKey RPC failed")?
                    .into_inner();
                println!("{}", resp.sha256_prefix);
            }
            cli::ManageKeysCommand::Remove(r) => {
                let resp = c
                    .remove_api_key(RemoveApiKeyRequest { key: r.key })
                    .await
                    .context("RemoveApiKey RPC failed")?
                    .into_inner();
                println!("{}\t{}", resp.removed, resp.sha256_prefix);
            }
        },
        cli::ManageCommands::InspectPcap(_) => {}
    }

    Ok(())
}

fn inspect_pcap(
    path: &Path,
    limit: usize,
    payload: InspectPayloadMode,
    mime: bool,
    gzip_decode: bool,
    zip_decode: bool,
) -> Result<()> {
    use pcap_file::pcap::PcapReader;

    let file = std::fs::File::open(path)
        .with_context(|| format!("failed to open pcap: {}", path.display()))?;

    let mut reader = PcapReader::new(file).context("failed to parse pcap")?;

    let mut i = 0usize;
    while let Some(pkt) = reader.next_packet() {
        let pkt = pkt.context("failed to read packet")?;
        i += 1;
        if limit > 0 && i > limit {
            break;
        }

        let data = pkt.data;
        println!("#{} ts={:?} len={}", i, pkt.timestamp, data.len());

        if let Ok(eth) = etherparse::Ethernet2HeaderSlice::from_slice(&data) {
            let src = eth.source();
            let dst = eth.destination();
            println!(
                "eth src={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} dst={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} type=0x{:04x}",
                src[0], src[1], src[2], src[3], src[4], src[5],
                dst[0], dst[1], dst[2], dst[3], dst[4], dst[5],
                u16::from(eth.ether_type())
            );
        }

        let mut payload_bytes: &[u8] = &[];

        if let Ok(sliced) = etherparse::SlicedPacket::from_ethernet(&data) {
            if let Some(net) = &sliced.net {
                match net {
                    etherparse::NetSlice::Ipv4(ip) => {
                        println!(
                            "ipv4 {} -> {} proto={} ttl={}",
                            std::net::Ipv4Addr::from(ip.header().source()),
                            std::net::Ipv4Addr::from(ip.header().destination()),
                            u8::from(ip.header().protocol()),
                            ip.header().ttl()
                        );
                    }
                    etherparse::NetSlice::Ipv6(ip) => {
                        println!(
                            "ipv6 {} -> {} next_header={} hop_limit={}",
                            std::net::Ipv6Addr::from(ip.header().source()),
                            std::net::Ipv6Addr::from(ip.header().destination()),
                            u8::from(ip.header().next_header()),
                            ip.header().hop_limit()
                        );
                    }
                }
            }

            if let Some(transport) = sliced.transport {
                match transport {
                    etherparse::TransportSlice::Tcp(tcp) => {
                        println!(
                            "tcp {} -> {} seq={} ack={} win={}",
                            tcp.source_port(),
                            tcp.destination_port(),
                            tcp.sequence_number(),
                            tcp.acknowledgment_number(),
                            tcp.window_size()
                        );
                        payload_bytes = tcp.payload();
                    }
                    etherparse::TransportSlice::Udp(udp) => {
                        println!("udp {} -> {} len={}", udp.source_port(), udp.destination_port(), udp.length());
                        payload_bytes = udp.payload();
                    }
                    etherparse::TransportSlice::Icmpv4(icmp) => {
                        println!("icmpv4 type={} code={}", icmp.type_u8(), icmp.code_u8());
                    }
                    etherparse::TransportSlice::Icmpv6(icmp) => {
                        println!("icmpv6 type={} code={}", icmp.type_u8(), icmp.code_u8());
                    }
                    _ => {}
                }
            }
        }

        if !payload_bytes.is_empty() {
            if mime {
                if let Some(kind) = infer::get(payload_bytes) {
                    println!("mime {} ({})", kind.mime_type(), kind.extension());
                } else if std::str::from_utf8(payload_bytes).is_ok() {
                    println!("mime text/plain (utf-8)");
                } else {
                    println!("mime application/octet-stream");
                }
            }

            let mut view = payload_bytes.to_vec();
            if gzip_decode && view.len() >= 2 && view[0] == 0x1f && view[1] == 0x8b {
                let mut gz = flate2::read::GzDecoder::new(view.as_slice());
                let mut out = Vec::new();
                if gz.read_to_end(&mut out).is_ok() {
                    view = out;
                    println!("gzip_decoded_len={}", view.len());
                }
            }

            if zip_decode && view.len() >= 4 && view[0] == 0x50 && view[1] == 0x4b {
                let cursor = Cursor::new(view.clone());
                if let Ok(mut archive) = zip::ZipArchive::new(cursor) {
                    println!("zip_entries={}", archive.len());
                    for idx in 0..archive.len() {
                        if let Ok(f) = archive.by_index(idx) {
                            println!("zip_entry name={} size={}", f.name(), f.size());
                        }
                    }

                    // Extract the first reasonably sized entry for optional MIME sniff + payload display.
                    // Hard limit to avoid pathological archives.
                    const MAX_EXTRACT: u64 = 1024 * 1024;
                    if archive.len() > 0 {
                        if let Ok(mut f) = archive.by_index(0) {
                            if f.size() <= MAX_EXTRACT {
                                let mut out = Vec::new();
                                if f.read_to_end(&mut out).is_ok() {
                                    view = out;
                                    println!("zip_extracted_len={}", view.len());
                                }
                            }
                        }
                    }
                }
            }

            match payload {
                InspectPayloadMode::None => {}
                InspectPayloadMode::Ascii => {
                    let s = String::from_utf8_lossy(&view);
                    println!("payload_ascii:\n{}", s);
                }
                InspectPayloadMode::Hex => {
                    println!("payload_hex:\n{}", hex::encode(&view));
                }
            }
        }

        println!();
    }

    Ok(())
}

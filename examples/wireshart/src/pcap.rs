use async_std::io::{BufRead, ReadExt};
use etherparse::err::{ip, ipv4};
use iced::futures::{SinkExt, Stream, StreamExt};
use iced::stream::try_channel;
use iced::widget::Row;
use pcap_parser::nom::Slice;
use pcap_parser::traits::PcapReaderIterator;
use pcap_parser::{create_reader, LegacyPcapReader, PcapError};

#[derive(Debug, Clone)]
pub struct PcapSimpleRow {
    pub counter: usize,
    // pub offset: usize,
    pub source_ip: smol_str::SmolStr,
    pub destination_ip: smol_str::SmolStr,
    pub source_port: u16,
    pub destination_port: u16,
    pub payload_len: usize,
    pub reader:
        std::sync::Arc<std::sync::Mutex<std::io::BufReader<std::fs::File>>>,
    pub pcap_offset: usize,
}

pub fn convert_pcap_block(
    reader: std::sync::Arc<std::sync::Mutex<std::io::BufReader<std::fs::File>>>,
    counter: usize,
    pcap_offset: usize,
    block: &[u8],
) -> Option<PcapSimpleRow> {
    // Ethernet
    let start_offset = 0;
    let end_offset = start_offset + etherparse::Ethernet2Header::LEN;

    let ethernet_header = etherparse::Ethernet2HeaderSlice::from_slice(
        block.slice(start_offset..end_offset),
    )
    .ok()
    .unwrap();

    if ethernet_header.ether_type() != etherparse::EtherType::IPV4 {
        return None;
    }

    // IPV4

    let start_offset = end_offset;
    let end_offset = start_offset + etherparse::Ipv4Header::MIN_LEN;

    let ipv4_header = etherparse::Ipv4HeaderSlice::from_slice(
        block.slice(start_offset..end_offset),
    )
    .ok()
    .unwrap();

    if ipv4_header.protocol() != etherparse::IpNumber::UDP {
        return None;
    }

    let end_offset = end_offset + ipv4_header.options().len();

    // UDP

    let start_offset = end_offset;
    let end_offset = start_offset + etherparse::UdpHeader::LEN;

    let udp_header = etherparse::UdpHeaderSlice::from_slice(
        block.slice(start_offset..end_offset),
    )
    .ok()
    .unwrap();

    // Payload

    assert!(udp_header.length() as usize >= etherparse::UdpHeader::LEN);
    // let start_offset = end_offset;
    // let end_offset = start_offset + udp_header.length() as usize
    //     - etherparse::UdpHeader::LEN;

    Some(PcapSimpleRow {
        counter,
        source_ip: smol_str::SmolStr::new_inline(
            ipv4_header.source_addr().to_string().as_str(),
        ),
        destination_ip: smol_str::SmolStr::new_inline(
            ipv4_header.destination_addr().to_string().as_str(),
        ),
        source_port: udp_header.source_port(),
        destination_port: udp_header.destination_port(),
        payload_len: block.len(),
        reader,
        pcap_offset,
    })
}

fn open_file() -> std::io::BufReader<std::fs::File> {
    std::io::BufReader::new(
        std::fs::OpenOptions::new()
            .read(true)
            .open("/home/hbina085/Downloads/20220419_IEXTP1_TOPS1.6.pcap")
            // .open("/home/hbina085/Downloads/small.pcap")
            .unwrap(),
    )
}

pub fn process_pcap(
) -> impl Stream<Item = Result<PcapSimpleRow, PcapProcessError>> {
    try_channel(1, move |mut output| async move {
        let input_file =
            std::sync::Arc::new(std::sync::Mutex::new(open_file()));
        let mut pcap_reader =
            LegacyPcapReader::new(64 * 1024, open_file()).unwrap();
        let mut counter = 0;
        let mut pcap_offset = 0;
        loop {
            match pcap_reader.next() {
                Ok((current_offset, block)) => {
                    pcap_offset += current_offset;
                    println!(
                        "current_offset:{} pcap_offset:{}",
                        current_offset, pcap_offset
                    );
                    match block {
                        // pcap_parser::PcapBlockOwned::NG(ng) => match ng {
                        //     pcap_parser::Block::EnhancedPacket(b) => {
                        //         // println!("b:{}", b.data.len());
                        //         if let Some(b) = convert_pcap_block(
                        //             input_file.clone(),
                        //             counter,
                        //             pcap_offset,
                        //             b.data,
                        //         ) {
                        //             output.send(b).await.unwrap();
                        //             counter += 1;
                        //         }
                        //     }
                        //     pcap_parser::Block::SimplePacket(b) => {
                        //         // println!("b:{}", b.data.len());
                        //         if let Some(b) = convert_pcap_block(
                        //             input_file.clone(),
                        //             counter,
                        //             pcap_offset,
                        //             b.data,
                        //         ) {
                        //             output.send(b).await.unwrap();
                        //             counter += 1;
                        //         }
                        //     }
                        //     _ => {}
                        // },
                        pcap_parser::PcapBlockOwned::Legacy(b) => {
                            // println!("b:{}", b.data.len());
                            if let Some(b) = convert_pcap_block(
                                input_file.clone(),
                                counter,
                                pcap_offset + 16,
                                b.data,
                            ) {
                                output.send(b).await.unwrap();
                                counter += 1;
                            }
                        }
                        _ => {}
                    }

                    // println!(
                    //     "counter:{} offset:{} total_offset:{}",
                    //     counter, current_offset, pcap_offset
                    // );
                    pcap_reader.consume(current_offset);
                }
                Err(PcapError::Eof) => break,
                Err(PcapError::Incomplete(_)) => {
                    pcap_reader.refill().unwrap();
                }
                Err(e) => break,
            }
        }

        // let _ = output.send(Progress::Finished).await;

        Ok(())
    })
}

#[derive(Debug, Clone)]
pub enum PcapProcessError {
    RequestFailed(std::sync::Arc<reqwest::Error>),
    NoContentLength,
}

impl From<reqwest::Error> for PcapProcessError {
    fn from(error: reqwest::Error) -> Self {
        PcapProcessError::RequestFailed(std::sync::Arc::new(error))
    }
}

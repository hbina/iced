use iced::futures::{SinkExt, Stream, StreamExt};
use iced::stream::try_channel;
use pcap_parser::traits::PcapReaderIterator;
use pcap_parser::{LegacyPcapReader, PcapError};

#[derive(Debug, Clone)]
pub struct PcapPointer {
    // pub counter: usize,
    // // pub offset: usize,
    // pub source_ip: smol_str::SmolStr,
    // pub destination_ip: smol_str::SmolStr,
    // pub source_port: u16,
    // pub destination_port: u16,
    // pub payload_len: usize,
    pub reader: std::sync::Arc<std::sync::Mutex<std::fs::File>>,
    pub pcap_offset: usize,
    pub pcap_len: usize,
}

pub struct PcapPointerIterator {
    pcap_reader: LegacyPcapReader<std::io::BufReader<std::fs::File>>,
    pcap_offset: usize,
    reader: std::sync::Arc<std::sync::Mutex<std::fs::File>>,
}

impl PcapPointerIterator {
    pub fn new(file_path: &'static str) -> Self {
        Self {
            pcap_reader: LegacyPcapReader::new(
                64 * 1024 * 1024,
                std::io::BufReader::new(
                    std::fs::OpenOptions::new()
                        .read(true)
                        .open(file_path)
                        .unwrap(),
                ),
            )
            .unwrap(),
            pcap_offset: 0,
            reader: std::sync::Arc::new(std::sync::Mutex::new(
                std::fs::OpenOptions::new()
                    .read(true)
                    .open(file_path)
                    .unwrap(),
            )),
        }
    }
}

impl Iterator for PcapPointerIterator {
    type Item = PcapPointer;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match self.pcap_reader.next() {
                Ok((current_offset, block)) => {
                    println!(
                        "self.pcap_offset:{} current_offset:{}",
                        self.pcap_offset, current_offset
                    );
                    let res = match block {
                        pcap_parser::PcapBlockOwned::NG(ng) => match ng {
                            pcap_parser::Block::EnhancedPacket(b) => {
                                Some(PcapPointer {
                                    reader: self.reader.clone(),
                                    pcap_offset: self.pcap_offset,
                                    pcap_len: b.data.len(),
                                })
                            }
                            pcap_parser::Block::SimplePacket(b) => {
                                 Some(PcapPointer {
                                    reader: self.reader.clone(),
                                    pcap_offset: self.pcap_offset,
                                    pcap_len: b.data.len(),
                                })
                            }
                            _ => None,
                        },
                        pcap_parser::PcapBlockOwned::Legacy(b) => {
                             Some(PcapPointer {
                                reader: self.reader.clone(),
                                pcap_offset: self.pcap_offset,
                                pcap_len: b.data.len(),
                            })
                        }
                        _ => None,
                    };

                    self.pcap_offset += current_offset;
                    self.pcap_reader.consume(current_offset);

                    if let Some(res) = res {
                        return Some(res);
                    }
                }
                Err(PcapError::Eof) => break,
                Err(PcapError::Incomplete(_)) => {
                    self.pcap_reader.refill().unwrap();
                }
                Err(_) => break,
            }
        }

        return None;
    }
}

pub fn process_pcap(
    file_path: &'static str,
) -> impl Stream<Item = Result<PcapPointer, String>> {
    try_channel(1, move |mut output| async move {
        for pcap in PcapPointerIterator::new(file_path) {
            output.send(pcap).await.unwrap();
        }

        Ok(())
    })
}

// use std::io::Read;

// #[repr(C, packed)]
// #[derive(Copy, Clone, Debug)]
// pub struct PcapHeader {
//     pub magic_number: u32,
//     pub version_major: u16,
//     pub version_minor: u16,
//     pub thiszone: i32,
//     pub sigfigs: u32,
//     pub snaplen: u32,
//     pub network: u32,
//     // buffer: &'static [u8],
// }

// unsafe impl bytemuck::Zeroable for PcapHeader {}
// unsafe impl bytemuck::Pod for PcapHeader {}

// impl PcapHeader {
//     pub fn size() -> usize {
//         24
//     }
// }

// #[repr(C, packed)]
// #[derive(Copy, Clone, Debug)]
// pub struct PacketHeader {
//     pub ts: u32,
//     pub ns: u32,
//     pub captured_len: u32,
//     pub original_len: u32,
// }

// pub struct Engine {
//     reader: std::io::BufReader<std::fs::File>,
// }

// impl Engine {
//     pub fn new<I>(input_path: I) -> Engine
//     where
//         I: AsRef<std::path::Path>,
//     {
//         let file = std::fs::File::open(input_path).unwrap();
//         let reader = std::io::BufReader::new(file);
//         Engine { reader }
//     }

//     pub fn get_next(
//         &self,
//         original_start_offset: usize,
//     ) -> Option<&'static RawQuote> {
//         // Ethernet

//         let start_offset = original_start_offset;
//         let end_offset = start_offset + etherparse::Ethernet2Header::LEN;

//         let ethernet_header = etherparse::Ethernet2HeaderSlice::from_slice(
//             self.mmap.slice(start_offset..end_offset),
//         )
//         .ok()?;

//         if ethernet_header.ether_type() != etherparse::EtherType::IPV4 {
//             return None;
//         }

//         // IPV4

//         let start_offset = end_offset;
//         let end_offset = start_offset + etherparse::Ipv4Header::MIN_LEN;

//         let ipv4_header = etherparse::Ipv4HeaderSlice::from_slice(
//             self.mmap.slice(start_offset..end_offset),
//         )
//         .ok()?;

//         if ipv4_header.protocol() != etherparse::IpNumber::UDP {
//             return None;
//         }

//         // UDP

//         let start_offset = end_offset;
//         let end_offset = start_offset + etherparse::UdpHeader::LEN;

//         let udp_header = etherparse::UdpHeaderSlice::from_slice(
//             self.mmap.slice(start_offset..end_offset),
//         )
//         .ok()?;

//         if udp_header.destination_port() != 15515
//             && udp_header.destination_port() != 15516
//         {
//             return None;
//         }

//         // Payload

//         let start_offset = end_offset;
//         let end_offset = start_offset + udp_header.length() as usize - 8;

//         let payload = self.mmap.slice(start_offset..end_offset);

//         let data_header = DataHeader(payload.slice(0..DataHeader::LEN));

//         // println!("data_header:{:#?}", data_header);

//         if data_header.0 != [b'B', b'6', b'0', b'3', b'4'] {
//             return None;
//         }

//         let buffer = payload.slice(DataHeader::LEN..);
//         let raw_quote = bytemuck::try_from_bytes::<RawQuote>(buffer).unwrap();

//         Some(raw_quote)
//     }

//     pub fn start(&self) {
//         let mut buffer = vec![0; 512 * 1024 * 1024];
//         {
//             let mut tmp_buffer = [0; 24];
//             input_file.read_exact(&mut tmp_buffer).await.unwrap();
//         }
//         loop {
//             {
//                 let mut tmp_buffer = [0; 16];
//                 input_file.read_exact(&mut tmp_buffer).await.unwrap();
//             }
//             match reader.next() {
//                 Ok((offset, block)) => {
//                     println!("offset:{}", offset);
//                     match block {
//                         pcap_parser::PcapBlockOwned::NG(ng) => match ng {
//                             pcap_parser::Block::EnhancedPacket(b) => {
//                                 // output
//                                 //     .send(convert_pcap_block(offset, b.data))
//                                 //     .await
//                                 //     .unwrap();
//                             }
//                             pcap_parser::Block::SimplePacket(b) => {
//                                 // output
//                                 //     .send(convert_pcap_block(offset, b.data))
//                                 //     .await
//                                 //     .unwrap();
//                             }
//                             _ => continue,
//                         },
//                         pcap_parser::PcapBlockOwned::Legacy(b) => {
//                             // output
//                             //     .send(convert_pcap_block(offset, b.data))
//                             //     .await
//                             //     .unwrap();
//                         }
//                         _ => continue,
//                     }

//                     reader.consume(offset);
//                 }
//                 Err(PcapError::Eof) => break,
//                 Err(PcapError::Incomplete(_)) => {
//                     reader.refill().unwrap();
//                 }
//                 Err(e) => panic!("error while reading: {:?}", e),
//             }
//         }
//     }
// }

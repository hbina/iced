#[allow(non_camel_case_types)]
mod network_header;
mod pcap;

use iced::task;
use iced::widget::{
    button, center, column, progress_bar, scrollable, text, Column, Row,
};
use iced::Length::Fill;
use iced::{Center, Element, Right, Task};
use once_cell::sync::Lazy;
use std::io::{Read, Seek};

use pcap::{process_pcap, PcapProcessError, PcapSimpleRow};
use pcap_parser::nom::Slice;

static SCROLLABLE_ID: Lazy<scrollable::Id> = Lazy::new(scrollable::Id::unique);

pub fn main() -> iced::Result {
    iced::application("Wireshart", MainGui::update, MainGui::view).run()
}

#[derive(Debug)]
struct MainGui {
    // state: MainContainerState,
    rows: Vec<PcapSimpleRow>,
    expanded: std::collections::HashSet<usize>,
}

#[derive(Debug, Clone)]
pub enum MainGuiMessage {
    Start,
    NewRow(Result<PcapSimpleRow, PcapProcessError>),
    Expand(usize),
}

impl MainGui {
    fn update(&mut self, message: MainGuiMessage) -> Task<MainGuiMessage> {
        match message {
            MainGuiMessage::Start => {
                let task = self.start();
                task.map(move |progress| MainGuiMessage::NewRow(progress))
            }
            MainGuiMessage::NewRow(progress) => {
                self.progress(progress);
                Task::none()
            }
            MainGuiMessage::Expand(idx) => {
                println!("expanding {}", idx);
                self.expanded.insert(idx);
                Task::none()
            }
        }
    }

    pub fn start(&mut self) -> Task<Result<PcapSimpleRow, PcapProcessError>> {
        let (task, _) = Task::stream(process_pcap()).abortable();
        task
    }

    pub fn progress(
        &mut self,
        new_progress: Result<PcapSimpleRow, PcapProcessError>,
    ) {
        let new_progress = new_progress.unwrap();
        // println!("idx:{} offset:{}", self.rows.len(), new_progress.offset);
        self.rows.push(new_progress);
    }

    pub fn view(&self) -> Element<MainGuiMessage> {
        // let rows = Column::with_children(
        //     self.rows
        //         .iter()
        //         .map(|s: &usize| text!("Block size {s}").into()),
        // );

        let scrollable = scrollable(Column::with_children(
            self.rows.iter().enumerate().map(|(idx, r)| {
                create_pcap_block_widget(idx, self.expanded.contains(&idx), r)
                    .into()
            }),
        ))
        .direction(
            scrollable::Direction::Vertical(scrollable::Scrollbar::new()),
        )
        .width(Fill)
        .height(Fill)
        .id(SCROLLABLE_ID.clone());

        let control: Element<_> = button("Start processing")
            .on_press(MainGuiMessage::Start)
            .into();

        Column::new().push(control).push(scrollable).into()
    }
}

impl Default for MainGui {
    fn default() -> Self {
        Self {
            rows: Vec::default(),
            expanded: std::collections::HashSet::default(),
        }
    }
}

pub fn convert_pcap_block_to_rows<'a>(
    r: &PcapSimpleRow,
    block: &[u8],
) -> Column<'a, MainGuiMessage> {
    let mut rows = Column::new().push(text!(
        "{} {}:{} => {}:{} len:{}",
        r.counter,
        r.source_ip,
        r.source_port,
        r.destination_ip,
        r.destination_port,
        // r.offset,
        r.payload_len
    ));

    // Ethernet
    let start_offset = 0;
    let end_offset = start_offset + etherparse::Ethernet2Header::LEN;

    let ethernet_header = etherparse::Ethernet2HeaderSlice::from_slice(
        block.slice(start_offset..end_offset),
    )
    .ok()
    .unwrap();

    rows = rows.push(text!("L1:{:?}", ethernet_header));

    // IPV4

    let start_offset = end_offset;
    let end_offset = start_offset + etherparse::Ipv4Header::MIN_LEN;

    let ipv4_header = etherparse::Ipv4HeaderSlice::from_slice(
        block.slice(start_offset..end_offset),
    )
    .ok()
    .unwrap();

    rows = rows.push(text!("L2:{:?}", ipv4_header));

    let end_offset = end_offset + ipv4_header.options().len();

    // UDP

    let start_offset = end_offset;
    let end_offset = start_offset + etherparse::UdpHeader::LEN;

    let udp_header = etherparse::UdpHeaderSlice::from_slice(
        block.slice(start_offset..end_offset),
    )
    .ok()
    .unwrap();

    rows = rows.push(text!("L3:{:?}", udp_header));

    // Payload

    assert!(udp_header.length() as usize >= etherparse::UdpHeader::LEN);
    // let start_offset = end_offset;
    // let end_offset = start_offset + udp_header.length() as usize
    //     - etherparse::UdpHeader::LEN;

    rows = rows.push(
        button("Collapse").on_press_with(move || MainGuiMessage::Expand(0)),
    );

    rows
}

pub fn create_pcap_block_widget<'a>(
    idx: usize,
    expanded: bool,
    r: &PcapSimpleRow,
) -> Element<'a, MainGuiMessage> {
    if expanded {
        let mut buffer = vec![0; r.payload_len];
        {
            let mut reader = r.reader.lock().unwrap();
            reader
                .seek(std::io::SeekFrom::Start(r.pcap_offset as u64))
                .unwrap();
            reader.read(&mut buffer).unwrap();
        }
        return Element::new(convert_pcap_block_to_rows(r, &buffer));
    } else {
        Element::new(
            Row::new()
                .push(text!(
                    "{} {}:{} => {}:{} len:{}",
                    r.counter,
                    r.source_ip,
                    r.source_port,
                    r.destination_ip,
                    r.destination_port,
                    // r.offset,
                    r.payload_len
                ))
                .push(
                    button("Expand")
                        .on_press_with(move || MainGuiMessage::Expand(idx)),
                ),
        )
    }
}

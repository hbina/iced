#[derive(Debug, Clone)]
pub enum MainGuiMessage {
    Start,
    NewRow(Result<crate::l1::pcap::PcapPointer, String>),
    Expand(usize),
    Collapse(usize),
}

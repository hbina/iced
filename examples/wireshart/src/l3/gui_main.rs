static SCROLLABLE_ID: once_cell::sync::Lazy<iced::widget::scrollable::Id> =
    once_cell::sync::Lazy::new(iced::widget::scrollable::Id::unique);

#[derive(Debug)]
pub struct MainGui {
    // state: MainContainerState,
    rows: Vec<crate::l1::pcap::PcapPointer>,
    expanded: std::collections::HashSet<usize>,
}

impl MainGui {
    pub fn update(
        &mut self,
        message: crate::l2::core::MainGuiMessage,
    ) -> iced::Task<crate::l2::core::MainGuiMessage> {
        match message {
            crate::l2::core::MainGuiMessage::Start => {
                let task = self.start();
                task.map(move |progress| {
                    crate::l2::core::MainGuiMessage::NewRow(progress)
                })
            }
            crate::l2::core::MainGuiMessage::NewRow(progress) => {
                self.progress(progress);
                iced::Task::none()
            }
            crate::l2::core::MainGuiMessage::Expand(idx) => {
                self.expanded.insert(idx);
                iced::Task::none()
            }
            crate::l2::core::MainGuiMessage::Collapse(idx) => {
                self.expanded.remove(&idx);
                iced::Task::none()
            }
        }
    }

    pub fn start(
        &mut self,
    ) -> iced::Task<Result<crate::l1::pcap::PcapPointer, String>> {
        let (task, _) = iced::Task::stream(crate::l1::pcap::process_pcap(
            "/home/hbina085/Downloads/20220103_IEXTP1_TOPS1.6.pcap",
        ))
        .abortable();
        task
    }

    pub fn progress(
        &mut self,
        new_progress: Result<crate::l1::pcap::PcapPointer, String>,
    ) {
        let new_progress = new_progress.unwrap();
        // println!("idx:{} offset:{}", self.rows.len(), new_progress.offset);
        self.rows.push(new_progress);
    }

    pub fn view(&self) -> iced::Element<crate::l2::core::MainGuiMessage> {
        // let rows = Column::with_children(
        //     self.rows
        //         .iter()
        //         .map(|s: &usize| text!("Block size {s}").into()),
        // );

        let scrollable =
            iced::widget::scrollable(iced::widget::Column::with_children(
                self.rows.iter().enumerate().map(|(idx, r)| {
                    super::gui_pcap::create_pcap_block_widget(
                        idx,
                        self.expanded.contains(&idx),
                        r,
                    )
                    .into()
                }),
            ))
            .direction(iced::widget::scrollable::Direction::Vertical(
                iced::widget::scrollable::Scrollbar::new(),
            ))
            .width(iced::Fill)
            .height(iced::Fill)
            .id(SCROLLABLE_ID.clone());

        let control: iced::Element<_> =
            iced::widget::button("Start processing")
                .on_press(crate::l2::core::MainGuiMessage::Start)
                .into();

        iced::widget::Column::new()
            .push(control)
            .push(scrollable)
            .into()
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

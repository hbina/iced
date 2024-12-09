mod l1;
mod l2;
mod l3;

pub fn main() -> iced::Result {
    iced::application(
        "Wireshart",
        l3::gui_main::MainGui::update,
        l3::gui_main::MainGui::view,
    )
    .run()
}

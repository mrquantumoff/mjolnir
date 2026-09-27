use gpui_kit::component::button::*;
use gpui_kit::component::*;
use gpui_kit::*;

struct Hello;

impl Render for Hello {
    fn render(&mut self, _: &mut Window, _: &mut Context<Self>) -> impl IntoElement {
        div()
            .v_flex()
            .gap_2()
            .size_full()
            .items_center()
            .justify_center()
            .child("Hello, gorynych")
            .child(Button::new("ok").primary().label("Click"))
    }
}

fn main() {
    gpui_kit::application()
        .with_assets(gpui_kit::assets::Assets)
        .run(|cx| {
            gpui_kit::init(cx);
            cx.spawn(async move |cx| {
                cx.open_window(WindowOptions::default(), |window, cx| {
                    let view = cx.new(|_| Hello);
                    cx.new(|cx| Root::new(view, window, cx))
                })
                .expect("open window");
            })
            .detach();
        });
}

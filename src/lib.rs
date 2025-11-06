mod fullbright;
mod preloader;

#[ctor::ctor]
fn safe_setup() {
    std::panic::set_hook(Box::new(move |_panic_info| {}));
    main();
}

fn main() {
    let _ = fullbright::patch_gfx_gamma();
}
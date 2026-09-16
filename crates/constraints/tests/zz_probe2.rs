//! TEMPORARY probe — delete after running.
use constraints::lookup::check_discharge;
use constraints::memory;

#[test]
fn probe_frame_discharge() {
    let a = memory::family_frame_artifact(constants::family::ADD_SUB_LUI_AUIPC, 20);
    println!("lookups = {}", a.lookups.len());
    println!("outputs = {}", a.outputs.len());
    println!("discharge [] = {:?}", check_discharge(&a, &[]));
    let w = memory::image_window_artifact(20);
    println!(
        "window lookups = {}, discharge [] = {:?}",
        w.lookups.len(),
        check_discharge(&w, &[])
    );
}

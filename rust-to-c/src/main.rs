extern {
    fn buggy_c_code();
}

fn main() {
    println!("Calling buggy_c_code...");
    unsafe { buggy_c_code(); }
}

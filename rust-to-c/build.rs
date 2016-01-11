extern crate gcc;

fn main() {
    gcc::Config::new().file("src/buggy.c").compile("libbuggy.a");
}

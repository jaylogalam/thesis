#[allow(dead_code)] // not wired into the CLI yet
mod core;
mod cli;

fn main() {
    std::process::exit(cli::run(std::env::args().skip(1)));
}

//! Binary entry point of the fixture workspace.

mod util;

use netlib::socket;

fn main() {
    netlib::run();
    socket::create();
    ffiwrap::create_socket();
    let converted = util::convert(42);
    println!("{converted}");

    let handler: fn() = netlib::run;
    handler();

    util::dispatch_dynamic(&util::Worker);
    util::ambiguous_call();
}

/// An unsafe fn that is never called: must be reported as unreachable.
unsafe fn dead_unsafe() {}

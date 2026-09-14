use std::io::{ErrorKind, Write};

pub fn out(args: std::fmt::Arguments<'_>) {
    let mut stdout = std::io::stdout().lock();
    if let Err(e) = stdout.write_fmt(args).and_then(|()| stdout.write_all(b"\n")) {
        if e.kind() == ErrorKind::BrokenPipe {
            std::process::exit(0);
        }
        eprintln!("error: stdout: {e}");
        std::process::exit(1);
    }
}

macro_rules! say {
    () => {
        $crate::say::out(format_args!(""))
    };
    ($($arg:tt)*) => {
        $crate::say::out(format_args!($($arg)*))
    };
}

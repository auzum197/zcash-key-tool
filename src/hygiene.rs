/// Stop a panic or a segfault from writing a seed into a core file.
///
/// This is the only `unsafe` in the crate. We drop the core-dump limit rather
/// than `mlock` the pages.
pub fn disable_core_dumps() {
    let limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    unsafe {
        libc::setrlimit(libc::RLIMIT_CORE, &limit);
    }
}

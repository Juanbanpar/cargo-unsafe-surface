//! Utilities exercising transmutes, function pointers, dynamic dispatch
//! and ambiguous method resolution.

/// Reinterprets an integer as a float (reachable transmute).
pub fn convert(x: u64) -> f64 {
    // SAFETY: any bit pattern is a valid f64.
    unsafe { core::mem::transmute::<u64, f64>(x) }
}

pub trait Job {
    fn work(&self);
}

pub struct Worker;

impl Job for Worker {
    fn work(&self) {}
}

/// Dynamic dispatch: the concrete impl is only known at the call site.
pub fn dispatch_dynamic(job: &dyn Job) {
    job.work();
}

struct Alpha;
struct Beta;

impl Alpha {
    fn name(&self) {}
}

impl Beta {
    fn name(&self) {}
}

/// Two candidates named `name`: the small ambiguity set becomes
/// inferred may-call edges to both candidates.
pub fn ambiguous_call() {
    let a = Alpha;
    a.name();
}

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use tracing::info;

pub struct TrackingAllocator;

static CURRENT_ALLOCATED: AtomicUsize = AtomicUsize::new(0);
static GLOBAL_PEAK_ALLOCATED: AtomicUsize = AtomicUsize::new(0);
static PHASE_PEAK_ALLOCATED: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for TrackingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            let current = CURRENT_ALLOCATED.fetch_add(layout.size(), Ordering::SeqCst) + layout.size();
            update_peak(&GLOBAL_PEAK_ALLOCATED, current);
            update_peak(&PHASE_PEAK_ALLOCATED, current);
        }
        ptr
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc_zeroed(layout) };
        if !ptr.is_null() {
            let current = CURRENT_ALLOCATED.fetch_add(layout.size(), Ordering::SeqCst) + layout.size();
            update_peak(&GLOBAL_PEAK_ALLOCATED, current);
            update_peak(&PHASE_PEAK_ALLOCATED, current);
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) };
        CURRENT_ALLOCATED.fetch_sub(layout.size(), Ordering::SeqCst);
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let new_ptr = unsafe { System.realloc(ptr, layout, new_size) };
        if !new_ptr.is_null() {
            match new_size.cmp(&layout.size()) {
                std::cmp::Ordering::Greater => {
                    let delta = new_size - layout.size();
                    let current = CURRENT_ALLOCATED.fetch_add(delta, Ordering::SeqCst) + delta;
                    update_peak(&GLOBAL_PEAK_ALLOCATED, current);
                    update_peak(&PHASE_PEAK_ALLOCATED, current);
                }
                std::cmp::Ordering::Less => {
                    CURRENT_ALLOCATED.fetch_sub(layout.size() - new_size, Ordering::SeqCst);
                }
                std::cmp::Ordering::Equal => {}
            }
        }
        new_ptr
    }
}

fn update_peak(peak: &AtomicUsize, current: usize) {
    let mut prev = peak.load(Ordering::SeqCst);
    while current > prev {
        match peak.compare_exchange(prev, current, Ordering::SeqCst, Ordering::SeqCst) {
            Ok(_) => break,
            Err(next) => prev = next,
        }
    }
}

pub fn current_allocated() -> usize {
    CURRENT_ALLOCATED.load(Ordering::SeqCst)
}

pub fn global_peak_allocated() -> usize {
    GLOBAL_PEAK_ALLOCATED.load(Ordering::SeqCst)
}

pub fn reset_phase_peak() -> usize {
    let current = current_allocated();
    PHASE_PEAK_ALLOCATED.store(current, Ordering::SeqCst);
    current
}

pub fn phase_peak_allocated() -> usize {
    PHASE_PEAK_ALLOCATED.load(Ordering::SeqCst)
}

pub fn log_phase(label: &str, start_current: usize) {
    let current = current_allocated();
    let phase_peak = phase_peak_allocated();
    let delta = current as isize - start_current as isize;
    let peak_delta = phase_peak.saturating_sub(start_current);
    info!(
        "memory[{label}] current={}B ({:.2} KiB), delta={}B, phase_peak={}B ({:.2} KiB), phase_peak_delta={}B",
        current,
        bytes_to_kib(current),
        delta,
        phase_peak,
        bytes_to_kib(phase_peak),
        peak_delta
    );
}

pub fn log_checkpoint(label: &str) {
    let current = current_allocated();
    let phase_peak = phase_peak_allocated();
    let global_peak = global_peak_allocated();
    info!(
        "memory[{label}] current={}B ({:.2} KiB), phase_peak={}B ({:.2} KiB), global_peak={}B ({:.2} KiB)",
        current,
        bytes_to_kib(current),
        phase_peak,
        bytes_to_kib(phase_peak),
        global_peak,
        bytes_to_kib(global_peak),
    );
}

fn bytes_to_kib(bytes: usize) -> f64 {
    bytes as f64 / 1024.0
}

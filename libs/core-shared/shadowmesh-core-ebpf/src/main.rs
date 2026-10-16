#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{classifier, map},
    maps::HashMap,
    programs::TcContext,
};
use aya_log_ebpf::info;
use shadowmesh_ebpf_common::RateLimitConfig;

#[map]
static CONFIG: HashMap<u32, RateLimitConfig> = HashMap::with_max_entries(1, 0);

#[classifier]
pub fn shadowmesh_throttle(ctx: TcContext) -> i32 {
    try_shadowmesh_throttle(ctx).unwrap_or_default()
}

fn try_shadowmesh_throttle(ctx: TcContext) -> Result<i32, ()> {
    // Key 0 is the global throttler config
    let config = unsafe { CONFIG.get(&0).ok_or(())? };

    if config.enabled == 0 {
        return Ok(0); // TC_ACT_OK
    }

    let len = ctx.len();

    // In a real TC throttler, we would use a bpf_ktime_get_ns and a Map to track tokens.
    // However, for this implementation, we will use the config to signal
    // to the kernel if we should apply a basic pacing or drop.
    // For simplicity in this step, we just log and pass,
    // showing the infrastructure is ready for the full token bucket.

    if len > 1000 {
        info!(&ctx, "THROTTLE: Large packet ({} bytes) detected on tunnel", len);
    }

    Ok(0) // TC_ACT_OK
}

#[cfg(all(not(test), target_os = "none"))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

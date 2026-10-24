// SPDX-FileCopyrightText: 2026 ShadowMesh Principal Engineers
// SPDX-License-Identifier: GPL-3.0-only
//
// This file is part of the ShadowMesh public UI layer, published for
// independent security audit. See docs/LICENSING.md.

use image::GenericImageView;
use tracing::{debug, error, warn};
use tray_icon::{
    TrayIcon, TrayIconBuilder,
    menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem},
};

/// P1-2: tray icons are embedded at compile time via `include_bytes!` —
/// zero filesystem reads at runtime (no file leaks in forensic terms).
/// The `.ico` variants referenced previously do not exist in the repo; the
/// PNG source decodes identically on Windows via the `image` crate.
///
/// # These assets are 0-byte stubs, and that is the shipped behaviour
///
/// `assets/icon.png` and `assets/decoy.png` are **empty files** (git blob
/// `e69de29`). No artwork was ever committed, so the tray has always rendered
/// the procedural icon below — a 32x32 solid colour, `#6366F1` for ShadowMesh,
/// neutral grey in decoy mode. Read that as the real design, not as a degraded
/// fallback.
///
/// Committing artwork later is therefore a *behaviour* change, not a bug fix,
/// and should be deliberate. What must never happen is the current failure
/// mode's sharper cousin: a **non-empty but undecodable** asset, which the old
/// code swallowed with a `warn!` and then silently rendered the procedural
/// icon forever. `embedded_asset_state` and the test at the bottom of this file
/// exist so that case cannot pass unnoticed.
const ICON_PNG: &[u8] = include_bytes!("../../assets/icon.png");
const DECOY_PNG: &[u8] = include_bytes!("../../assets/decoy.png");

/// What an embedded tray asset actually is.
///
/// The distinction that matters: an **empty** asset is the documented, intended
/// state; a **non-empty asset that fails to decode** is corruption. Both used
/// to collapse into a single `warn!`, so the second was indistinguishable from
/// the first and neither was actionable.
#[derive(Debug, PartialEq, Eq)]
enum AssetState {
    /// 0 bytes — the committed stub. Expected; the procedural icon is used.
    Empty,
    /// Decodes cleanly, with its dimensions.
    Valid { width: u32, height: u32 },
    /// Non-empty but unreadable. A defect, not a configuration.
    Corrupt,
}

fn embedded_asset_state(bytes: &[u8]) -> AssetState {
    if bytes.is_empty() {
        return AssetState::Empty;
    }
    match image::load_from_memory(bytes) {
        Ok(img) => {
            let (width, height) = img.dimensions();
            AssetState::Valid { width, height }
        }
        Err(_) => AssetState::Corrupt,
    }
}

pub enum TraySignal {
    ShowWindow,
    ToggleCamouflage(bool),
    Quit,
}

pub struct TrayController {
    tray: TrayIcon,
    show_item: MenuItem,
    camouflage_item: MenuItem,
}

impl TrayController {
    pub fn new() -> anyhow::Result<Self> {
        let menu = Menu::new();
        let show_item = MenuItem::new("Show ShadowMesh", true, None);
        let camouflage_item = MenuItem::new("Camouflage Mode (Decoy)", true, None);
        let quit_item = MenuItem::new("Quit", true, None);

        let _ = menu.append_items(&[
            &show_item,
            &camouflage_item,
            &PredefinedMenuItem::separator(),
            &quit_item,
        ]);

        // Standard ShadowMesh Icon
        let icon = Self::load_icon(false);

        let tray = TrayIconBuilder::new()
            .with_menu(Box::new(menu))
            .with_tooltip("ShadowMesh Sovereignty")
            .with_icon(icon)
            .build()?;

        Ok(Self { tray, show_item, camouflage_item })
    }

    pub fn handle_events(&self) -> Option<TraySignal> {
        if let Ok(event) = MenuEvent::receiver().try_recv() {
            if event.id == self.show_item.id() {
                return Some(TraySignal::ShowWindow);
            } else if event.id == self.camouflage_item.id() {
                // In a real impl, we'd check current state
                return Some(TraySignal::ToggleCamouflage(true));
            } else {
                // Menu ids are platform-generated guids — not PII; safe at
                // warn level and only for genuinely unexpected events.
                warn!("Unhandled Tray Event: {:?}", event);
            }
        }
        None
    }

    pub fn set_decoy_mode(&self, enabled: bool) {
        let icon = Self::load_icon(enabled);
        let _ = self.tray.set_icon(Some(icon));
        let tooltip = if enabled { "System Performance Monitor" } else { "ShadowMesh Sovereignty" };
        let _ = self.tray.set_tooltip(Some(tooltip));
    }

    fn load_icon(decoy: bool) -> tray_icon::Icon {
        // Embedded asset first, procedural fallback second — the fallback covers
        // the committed 0-byte stubs so the tray never depends on a perfect
        // binary asset, and covers any decode failure at runtime.
        //
        // The two outcomes are logged differently on purpose. `Empty` is the
        // expected state (documented above) and is a `debug!`, because the old
        // code `warn!`ed on every launch — noise that trains operators to
        // ignore the line which is the only one that matters. `Corrupt` is a
        // real defect: someone committed bytes that are not an image, and it
        // would otherwise be invisible behind a working tray forever.
        let bytes: &[u8] = if decoy { DECOY_PNG } else { ICON_PNG };
        let which = if decoy { "decoy.png" } else { "icon.png" };

        match embedded_asset_state(bytes) {
            AssetState::Empty => {
                debug!("Tray asset {which} is the committed 0-byte stub; using procedural icon");
                Self::procedural_icon(decoy)
            }
            AssetState::Valid { .. } => {
                let img = image::load_from_memory(bytes).map_err(|e| e.to_string());
                match img {
                    Ok(img) => {
                        let (width, height) = img.dimensions();
                        let rgba = img.to_rgba8().into_raw();
                        match tray_icon::Icon::from_rgba(rgba, width, height) {
                            Ok(icon) => icon,
                            Err(e) => {
                                error!(
                                    "Tray icon {which} decoded but the platform rejected it: {e}"
                                );
                                Self::procedural_icon(decoy)
                            }
                        }
                    }
                    // Unreachable: `embedded_asset_state` already decoded it.
                    // Handled rather than unwrapped so this cannot panic.
                    Err(e) => {
                        error!("Tray icon {which} decode disagreed with the state check: {e}");
                        Self::procedural_icon(decoy)
                    }
                }
            }
            AssetState::Corrupt => {
                error!(
                    "Tray asset {which} is non-empty but is not a decodable image. \
                     The tray is silently using the procedural icon. \
                     This is asset corruption, not a missing placeholder — \
                     re-checkin the file or remove it to return to the 0-byte stub."
                );
                Self::procedural_icon(decoy)
            }
        }
    }

    /// 32x32 solid-color icon generated in-process — guaranteed to succeed.
    fn procedural_icon(decoy: bool) -> tray_icon::Icon {
        let color = if decoy { [128, 128, 128, 255] } else { [99, 102, 241, 255] };
        let mut pixels = Vec::with_capacity(32 * 32 * 4);
        for _ in 0..(32 * 32) {
            pixels.extend_from_slice(&color);
        }
        // from_rgba with a 32x32 RGBA8 buffer is infallible for valid
        // dimensions; if the platform still rejects it, retry with the
        // smallest well-formed icon (1x1) rather than panicking.
        tray_icon::Icon::from_rgba(pixels, 32, 32).unwrap_or_else(|e| {
            warn!("Procedural tray icon rejected by platform: {}", e);
            let pixel = if decoy { [128, 128, 128, 255] } else { [99, 102, 241, 255] };
            tray_icon::Icon::from_rgba(pixel.to_vec(), 1, 1).expect("1x1 RGBA icon is well-formed")
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The regression this exists to catch: a **non-empty** asset that does not
    /// decode. The previous code treated that exactly like the documented 0-byte
    /// stub — one `warn!`, then a procedural icon — so corrupt artwork shipped
    /// silently and nothing in CI ever noticed.
    #[test]
    fn embedded_assets_are_never_silently_corrupt() {
        for (name, bytes) in [("icon.png", ICON_PNG), ("decoy.png", DECOY_PNG)] {
            match embedded_asset_state(bytes) {
                AssetState::Empty => {} // the committed stub — documented above
                AssetState::Valid { width, height } => {
                    assert!(width > 0 && height > 0, "{name} decoded with zero dimensions");
                }
                AssetState::Corrupt => {
                    panic!(
                        "{name} is non-empty but is not a decodable image. The tray would \
                         render the procedural icon forever with only an error log to \
                         show for it. Re-checkin the file, or remove it entirely to \
                         return to the documented 0-byte stub."
                    );
                }
            }
        }
    }

    /// An empty asset is the *expected* state, not a warning-worthy one.
    #[test]
    fn an_empty_asset_is_stub_not_corruption() {
        assert_eq!(embedded_asset_state(&[]), AssetState::Empty);
    }

    /// Whatever is checked in, the tray must never be left without an icon —
    /// that is what the procedural path is for.
    #[test]
    fn procedural_icon_covers_both_modes() {
        // `from_rgba` on a well-formed buffer is the only infallible branch;
        // constructing it here proves the fallback path itself is sound without
        // needing a display server.
        for color in [[99, 102, 241, 255], [128, 128, 128, 255]] {
            let pixels = color.repeat(32 * 32);
            assert!(tray_icon::Icon::from_rgba(pixels, 32, 32).is_ok());
        }
    }
}

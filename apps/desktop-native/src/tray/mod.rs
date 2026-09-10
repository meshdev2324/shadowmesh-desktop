// SPDX-FileCopyrightText: 2026 ShadowMesh Principal Engineers
// SPDX-License-Identifier: GPL-3.0-only
//
// This file is part of the ShadowMesh public UI layer, published for
// independent security audit. See docs/LICENSING.md.

use image::GenericImageView;
use tracing::warn;
use tray_icon::{
    TrayIcon, TrayIconBuilder,
    menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem},
};

/// P1-2: tray icons are embedded at compile time via `include_bytes!` —
/// zero filesystem reads at runtime (no file leaks in forensic terms).
/// The `.ico` variants referenced previously do not exist in the repo; the
/// PNG source decodes identically on Windows via the `image` crate.
const ICON_PNG: &[u8] = include_bytes!("../../assets/icon.png");
const DECOY_PNG: &[u8] = include_bytes!("../../assets/decoy.png");

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
        // P1-2: embedded asset first, procedural fallback second — the
        // fallback covers empty/placeholder check-in assets and any decode
        // failure, so the tray never depends on a perfect binary asset.
        let bytes: &[u8] = if decoy { DECOY_PNG } else { ICON_PNG };

        match image::load_from_memory(bytes) {
            Ok(img) => {
                let (width, height) = img.dimensions();
                let rgba = img.to_rgba8().into_raw();
                match tray_icon::Icon::from_rgba(rgba, width, height) {
                    Ok(icon) => icon,
                    Err(e) => {
                        warn!("Tray icon decode failed, using procedural fallback: {}", e);
                        Self::procedural_icon(decoy)
                    }
                }
            }
            Err(e) => {
                // Expected while the placeholder PNGs are 0-byte check-in
                // stubs; the procedural fallback keeps the tray functional.
                warn!("Embedded tray icon undecodable, using procedural fallback: {}", e);
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

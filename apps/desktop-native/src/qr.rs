//! v2 pairing UX: renders the pairing payload as a scannable QR image for
//! the Slint UI. Payload is the pairing URI scheme plus the session token
//! so the phone's scanner can distinguish a pairing session from an access
//! code. Pure pixel math — no I/O, no process execution.

/// The URI payload encoded in the QR (single source of truth for both the
/// renderer and any future consumer that needs to validate a scanned code).
/// The token is a server-issued UUID; the scheme prefix is a fixed literal.
pub fn pairing_uri(token: &str) -> String {
    let scheme: &str = "shadowmesh://pair/";
    let mut payload = String::with_capacity(scheme.len() + token.len());
    payload.push_str(scheme);
    payload.push_str(token);
    payload
}

/// Renders a QR image for the given pairing token. The 2-module quiet zone
/// plus the white backdrop supplied by the Slint panel guarantee scanner
/// readability on the dark theme. Call on the UI thread (slint::Image is
/// not Send).
pub fn pairing_qr_image(token: &str) -> Option<slint::Image> {
    let payload = pairing_uri(token);
    let level: qrcode::EcLevel = qrcode::EcLevel::M;
    let code = qrcode::QrCode::with_error_correction_level(payload.as_bytes(), level).ok()?;
    let colors = code.to_colors();
    let modules = code.width();
    // 2-module quiet zone + 6 px per module: crisp, phone-scannable size.
    const QUIET: i64 = 2;
    const SCALE: i64 = 6;
    let dim_i = (modules as i64) + QUIET * 2;
    let dim = (dim_i * SCALE) as u32;

    // Raw RGBA8 bytes, row-major, then reinterpreted as Rgba8Pixel rows.
    let mut bytes: Vec<u8> = Vec::with_capacity(dim as usize * dim as usize * 4);
    for y in 0..dim_i {
        for x in 0..dim_i {
            let mx = x / SCALE - QUIET;
            let my = y / SCALE - QUIET;
            let in_bounds =
                mx >= 0 && my >= 0 && (mx as usize) < modules && (my as usize) < modules;
            let dark: bool =
                in_bounds && colors[my as usize * modules + mx as usize] == qrcode::Color::Dark;
            // Dark modules: near-black; light modules + quiet zone: white.
            let rgb: [u8; 3] = if dark { [0x0A, 0x0A, 0x12] } else { [0xFF, 0xFF, 0xFF] };
            bytes.extend_from_slice(&[rgb[0], rgb[1], rgb[2], 0xFF]);
        }
    }
    let buf = slint::SharedPixelBuffer::<slint::Rgba8Pixel>::clone_from_slice(&bytes, dim, dim);
    Some(slint::Image::from_rgba8(buf))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pairing_uri_shape() {
        assert_eq!(pairing_uri("abc-123"), "shadowmesh://pair/abc-123");
    }

    #[test]
    fn qr_renders_square_with_quiet_zone() {
        let img = pairing_qr_image("01234567-89ab-cdef-0123-456789abcdef").expect("renders");
        let size = img.size();
        // 32-char dashed UUID → ~33 modules; 33 + 4 quiet = 37 × 6 = 222.
        assert_eq!(size.width, size.height, "QR must be square");
        assert!(size.width >= 150, "QR large enough to scan: {}", size.width);
    }
}

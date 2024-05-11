use rand::Rng;

pub fn process_genpass(
    length: u8,
    upper: bool,
    lower: bool,
    number: bool,
    symbol: bool,
) -> anyhow::Result<String> {
    let mut rng = rand::thread_rng();
    let mut password = String::new();
    let mut chars = Vec::new();

    if upper {
        chars.extend_from_slice(b"ABCDEFGHJKLMNPQRSTUVWXYZ");
    }

    if lower {
        chars.extend_from_slice(b"abcdefghijkmnopqrstuvwxyz");
    }

    if number {
        chars.extend_from_slice(b"123456789");
    }

    if symbol {
        chars.extend_from_slice(b"!@#$%^&*_");
    }

    for _ in 0..length {
        let idx = rng.gen_range(0..chars.len());
        password.push(chars[idx] as char);
    }

    Ok(password)
}

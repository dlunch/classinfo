pub fn convert_pointer(raw: &[u8], pointer_size: usize) -> u64 {
    let value = &raw[0..pointer_size];

    if pointer_size == 8 {
        u64::from_le_bytes(value.try_into().unwrap())
    } else {
        u32::from_le_bytes(value.try_into().unwrap()) as u64
    }
}

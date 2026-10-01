//! Little-endian reads from untrusted bytes: `None` when the value would run
//! past the end of the slice, never a panic.

pub(crate) fn u16_le(data: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        data.get(at..at.checked_add(2)?)?.try_into().ok()?,
    ))
}

pub(crate) fn u32_le(data: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        data.get(at..at.checked_add(4)?)?.try_into().ok()?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_stop_at_the_end() {
        let data = [1, 2, 3, 4, 5, 6, 7, 8];
        assert_eq!(u16_le(&data, 0), Some(0x0201));
        assert_eq!(u32_le(&data, 4), Some(0x0807_0605));
        assert_eq!(u32_le(&data, 5), None);
        assert_eq!(u16_le(&data, usize::MAX), None);
    }
}

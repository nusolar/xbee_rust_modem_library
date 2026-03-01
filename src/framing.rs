use serde::{Serialize, de::DeserializeOwned};

pub fn encode_cobs<'a, T: Serialize>(
    msg: &T,
    out: &'a mut [u8],
) -> Result<&'a [u8], postcard::Error> {
    postcard::to_slice_cobs(msg, out).map(|s| &*s)
}

pub fn decode_cobs<T: DeserializeOwned>(
    frame_including_delim: &mut [u8],
) -> Result<T, postcard::Error> {
    postcard::from_bytes_cobs(frame_including_delim)
}
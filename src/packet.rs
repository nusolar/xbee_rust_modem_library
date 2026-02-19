use heapless::Vec;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct Packet {
    pub id: u32,
    pub payload: Vec<u8, 256>,
}

pub fn serialize_packet<'a>(
    packet: &Packet,
    buffer: &'a mut [u8],
) -> Result<&'a mut [u8], postcard::Error> {
    postcard::to_slice_cobs(packet, buffer)
}

pub fn deserialize_packet(serialized_packet: &mut [u8]) -> Result<Packet, postcard::Error> {
    postcard::from_bytes_cobs(serialized_packet)
}

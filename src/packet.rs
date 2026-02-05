use serde::{Serialize, Deserialize};
use postcard::{to_slice_cobs, from_bytes_cobs};
use heapless::Vec;

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct Packet {
    pub id: u32,
    pub payload: Vec<u8, 256>,
}

pub fn serialize_packet<'a>(packet: &Packet, buffer: &'a mut [u8]) -> Result<&'a mut [u8], postcard::Error> {
    postcard::to_slice_cobs(packet, buffer)
}

pub fn deserialize_packet<'a>(s_packet: &'a mut [u8]) -> Result<Packet, postcard::Error> 
where
    Packet: serde::Deserialize<'a>,
{
    postcard::from_bytes_cobs(s_packet)
}
/*
fn main() {
    let original_packet = Packet {
        id: 42,
        payload: Vec::from_slice(b"Hello, XBee!").unwrap(),
    };
    let mut buffer = [0u8; 512];


    let serialized_packet = serialize_packet(&original_packet, &mut buffer).unwrap();
    let deserialized_packet: Packet = deserialize_packet(serialized_packet).unwrap();

    assert_eq!(original_packet, deserialized_packet);
    println!("Packet serialized and deserialized successfully: {:?}", deserialized_packet);
}
*/
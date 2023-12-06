#![doc = include_str!("../README.md")]

use log::debug;
use num_enum::TryFromPrimitive;
use std::io::{Read, Seek, SeekFrom};

use crate::system_trace_event::SystemTraceEvent;

pub mod modern_event;
pub mod system_trace_event;

/// Trace Header formats
///
/// Events can be one of six different formats,
/// each having a 32-bit and a 64-bit version.
#[derive(Debug, Clone, Copy, Eq, PartialEq, TryFromPrimitive)]
#[repr(u8)]
pub enum TraceHeaderType {
    System32 = 0x01,
    System64 = 0x02,
    Compact32 = 0x03,
    Compact64 = 0x04,
    Perfinfo32 = 0x10,
    Perfinfo64 = 0x11,
    ModernEvent32 = 0x12,
    ModernEvent64 = 0x13,
    Full32 = 0x0A,
    Full64 = 0x14,
    Instance32 = 0x0B,
    Instance64 = 0x15,
}

#[non_exhaustive]
pub enum EtwEvent {
    ModernEvent(modern_event::ModernEvent),
    SystemTraceEvent(system_trace_event::SystemTraceEvent),
}

impl EtwEvent {
    pub fn get_event_type(&self) -> TraceHeaderType {
        match &self {
            EtwEvent::ModernEvent(event) => event.header.header_type,
            EtwEvent::SystemTraceEvent(event) => event.header.header_type,
        }
    }
}

pub fn parse_header<R: Read + Seek>(buf: &mut R) -> std::io::Result<EtwEvent> {
    let start = buf.stream_position()?;
    let mut header_type_bytes = [0u8; 4];
    buf.read_exact(&mut header_type_bytes)?;
    let header_type = TraceHeaderType::try_from(header_type_bytes[2]).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "encountered unknown TraceHeaderType!",
        )
    })?;
    buf.seek(SeekFrom::Start(start))?;

    match header_type {
        TraceHeaderType::System32 => Ok(EtwEvent::SystemTraceEvent(SystemTraceEvent::parse(buf)?)),

        TraceHeaderType::System64 => Ok(EtwEvent::SystemTraceEvent(SystemTraceEvent::parse(buf)?)),
        _ => unimplemented!(),
    }
}

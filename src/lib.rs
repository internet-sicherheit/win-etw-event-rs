#![doc = include_str!("../README.md")]

use log::trace;
use modern_event::ModernEvent;
use num_enum::TryFromPrimitive;
use std::io::{Error, Read, Seek, SeekFrom};

use crate::system_trace_event::SystemTraceEvent;

pub mod modern_event;
pub mod system_trace_event;

mod helper;

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
#[derive(Debug)]
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

    /// Size + 16 byte alignment
    ///
    /// The total space the event needs with 16 byte alignment.
    pub fn space(&self) -> u16 {
        let size = match self {
            EtwEvent::ModernEvent(e) => e.header.size,
            EtwEvent::SystemTraceEvent(e) => e.header.size,
        };
        size + (16 - size % 16)
    }
}

pub fn parse_header<R: Read + Seek>(buf: &mut R) -> std::io::Result<EtwEvent> {
    let start = buf.stream_position()?;
    let mut header_type_bytes = [0u8; 4];
    buf.read_exact(&mut header_type_bytes)?;

    trace!("Event header bytes: {:X?}", header_type_bytes);
    let header_type = TraceHeaderType::try_from(header_type_bytes[2]).map_err(|_| {
        trace!(
            "Encountered unknown TraceHeaderType 0x{:X} at stream position 0x{:X}",
            header_type_bytes[2],
            buf.stream_position().unwrap()
        );
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Encountered unknown TraceHeaderType!",
        )
    })?;
    buf.seek(SeekFrom::Start(start))?;

    match header_type {
        TraceHeaderType::System32 => Ok(EtwEvent::SystemTraceEvent(SystemTraceEvent::parse(buf)?)),
        TraceHeaderType::System64 => Ok(EtwEvent::SystemTraceEvent(SystemTraceEvent::parse(buf)?)),

        TraceHeaderType::ModernEvent32 => Ok(EtwEvent::ModernEvent(ModernEvent::parse(buf)?)),
        TraceHeaderType::ModernEvent64 => Ok(EtwEvent::ModernEvent(ModernEvent::parse(buf)?)),
        _ => {
            trace!(
                "Found event of type {:?} which is (not jet) supported.",
                header_type
            );
            Err(Error::new(
                std::io::ErrorKind::Unsupported,
                "Event type not supported (jet)",
            ))
        }
    }
}

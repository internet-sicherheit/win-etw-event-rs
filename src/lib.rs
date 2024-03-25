#![doc = include_str!("../README.md")]

use log::trace;
use modern_event::ModernEvent;
use num_enum::TryFromPrimitive;
use std::io::{Read, Seek, SeekFrom};

use crate::system_trace_event::SystemTraceEvent;

pub mod modern_event;
pub mod system_trace_event;
pub mod types;

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

/// A ETW event in one of the suported formats
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

    /// Size + 8 byte alignment
    ///
    /// The total space the event needs with 8 byte alignment.
    pub fn space(&self) -> u16 {
        let size = match self {
            EtwEvent::ModernEvent(e) => e.header.size,
            EtwEvent::SystemTraceEvent(e) => e.header.size,
        };
        size + (8 - size % 8)
    }

    /// Padding to the next event
    pub fn padding(&self) -> u8 {
        let size = match self {
            EtwEvent::ModernEvent(e) => e.header.size,
            EtwEvent::SystemTraceEvent(e) => e.header.size,
        };
        (8 - size % 8) as u8
    }
}

/// Parse a ETW event from a buffer
///
/// Parses the header of a ETW event and creates a event containing the header and payload.
pub fn parse_header<R: Read + Seek>(buf: &mut R) -> Result<EtwEvent, Error> {
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
            Err(Error::Unsupported)
        }
    }
}

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    // TraceHeader(std::io::Error),
    ModernEvent(modern_event::ModernEventError),
    Unsupported,
}
impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        Error::Io(value)
    }
}
impl From<modern_event::ModernEventError> for Error {
    fn from(value: modern_event::ModernEventError) -> Self {
        Error::ModernEvent(value)
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Io(_) => write!(f, "A error occured while reading data to parse an event."),
            Error::ModernEvent(_) => write!(f, "A error occured while parsing a modern event."),
            Error::Unsupported => write!(f, "Unsupported event type found."),
        }
    }
}

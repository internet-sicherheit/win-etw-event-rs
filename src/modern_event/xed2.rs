//! ## XED2 event format
//!
//! Non Microsoft Windows native event format.
//!
//! Designed to be used for events extracted via VMI (Virtual Machine Introspection).
use std::{
    ffi::CStr,
    io::{Cursor, Read},
};

use bitflags::bitflags;
use num_enum::TryFromPrimitive;
use serde::Serialize;
use uuid::Uuid;

use crate::helper::*;

use super::{types::EtwTimestamp, ModernEventError};

/// C API XED2 header size
const XED2_HEADER_SIZE: usize = 96;

/// XED2 binary event format
///
/// Can be converted into a [ModernEvent](super::ModernEvent).
///
/// _Note:_ Conversion to a [ModernEvent](super::ModernEvent) might fail,
/// if the if the XED2 event doesn't provide the necessary fields.  
/// Some fields of [ModernEvent](super::ModernEvent) might not be filled with acutal data.
#[derive(Debug, Clone)]
pub struct XED2Event {
    /// Fixed size header
    pub header: XED2EventHeader,
    /// Provider process name if available
    pub process_name: Option<String>,
    /// Provider executable path if available
    pub exe_path_name: Option<String>,
    /// Event payload
    ///
    /// Same format as payloads in [ModernEvents](super::ModernEvent).
    pub payload: Option<Vec<u8>>,
}

impl XED2Event {
    pub fn parse<R: Read>(buf: &mut R) -> Result<XED2Event, ModernEventError> {
        let mut size_bytes = [0u8; 2];
        buf.read_exact(&mut size_bytes)?;
        let size = u16_from_le_slice(&size_bytes)?;
        log::trace!("Parsing a event with size {size}");

        if (size as usize) < XED2_HEADER_SIZE {
            log::warn!("Read a event size of {size}, which is smaller than XED2_HEADER_SIZE ({XED2_HEADER_SIZE})");
            return Err(ModernEventError::new(
                crate::modern_event::ErrorType::InvalidHeader,
            ));
        }

        let mut event_bytes = vec![0u8; size as usize + padding_8_byte(size as usize) as usize];
        event_bytes[0] = size_bytes[0];
        event_bytes[1] = size_bytes[1];
        buf.read_exact(&mut event_bytes[2..])?;

        XED2Event::parse_slice(&event_bytes)
    }

    pub fn parse_slice(buf: &[u8]) -> Result<XED2Event, ModernEventError> {
        if buf.len() < XED2_HEADER_SIZE {
            return Err(ModernEventError::new(
                crate::modern_event::ErrorType::InvalidHeader,
            ));
        }
        let size = u16_from_le_slice(&buf[0..2])?;
        if buf.len() < size as usize {
            return Err(ModernEventError::new(
                crate::modern_event::ErrorType::InvalidHeader,
            ));
        }

        let buf = &buf[..size as usize];

        let xed2_header = XED2EventHeader::parse_slice(&buf[0..XED2_HEADER_SIZE])?;

        let (process_name, process_name_size) = if xed2_header
            .used_flags
            .contains(UsedFliedsFlags::ProcessName)
        {
            let c_str = CStr::from_bytes_until_nul(&buf[XED2_HEADER_SIZE..])
                .map_err(|_| ModernEventError::new(super::ErrorType::ParseError))?;
            (
                Some(String::from_utf8_lossy(c_str.to_bytes()).to_string()),
                c_str.to_bytes_with_nul().len(),
            )
        } else {
            (None, 0)
        };
        let exe_path_name = if xed2_header
            .used_flags
            .contains(UsedFliedsFlags::ExePathName)
        {
            // calculate the start of the exe path string:
            // xed2 header size + process name space + 2 byte padding
            let start = XED2_HEADER_SIZE
                + process_name_size
                + padding_2_byte(XED2_HEADER_SIZE + process_name_size) as usize;
            let exe_path = read_utf16_string_from_slice(&buf[start..])?;
            Some(exe_path)
        } else {
            None
        };

        let payload = if xed2_header.used_flags.contains(UsedFliedsFlags::Payload) {
            let start = xed2_header.header_size as usize
                + padding_8_byte(xed2_header.header_size as usize) as usize;
            let mut payload = Vec::with_capacity(buf.len() - start as usize);
            payload.extend_from_slice(&buf[start..]);
            Some(payload)
        } else {
            None
        };

        Ok(XED2Event {
            header: xed2_header,
            process_name,
            exe_path_name,
            payload,
        })
    }
}

/// XED2 binary event header format
#[derive(Debug, Clone)]
pub struct XED2EventHeader {
    pub size: u16,
    pub header_size: u16,
    pub extraction_method: ExtractionMethod,
    /// Indicate the used fields
    pub used_flags: UsedFliedsFlags,
    pub written_event_count: u64,
    pub captured_event_count: u64,
    pub timestamp: u64,
    pub provider_id: Option<Uuid>,
    pub event_id: Option<u16>,
    pub event_version: Option<u8>,
    pub event_channel: Option<u8>,
    pub event_level: Option<u8>,
    pub event_opcode: Option<u8>,
    pub event_task: Option<u16>,
    pub event_keywords: Option<u64>,
    pub thread_id: Option<u64>,
    pub process_id: Option<u64>,
    pub parent_process_id: Option<u64>,
    pub cpu_id: Option<u32>,
    pub irql: Option<u8>,
    pub payload_size: Option<u16>,
}
impl XED2EventHeader {
    fn parse_slice(buf: &[u8]) -> Result<XED2EventHeader, ModernEventError> {
        let size = u16_from_le_slice(&buf[0..2])?;
        let header_size = u16_from_le_slice(&buf[2..4])?;
        let extraction_method = ExtractionMethod::try_from(buf[4])
            .map_err(|_| ModernEventError::new(crate::modern_event::ErrorType::InvalidHeader))?;
        let used_flags = UsedFliedsFlags::from_bits(u16_from_le_slice(&buf[6..8])?).ok_or(
            ModernEventError::new(crate::modern_event::ErrorType::InvalidHeader),
        )?;
        let written_event_count = u64_from_le_slice(&buf[8..16])?;
        let captured_event_count = u64_from_le_slice(&buf[16..24])?;
        let timestamp = u64_from_le_slice(&buf[24..32])?;

        let provider_id = if used_flags.contains(UsedFliedsFlags::ProviderClassGUID) {
            Some(Uuid::from_slice_le(&buf[32..48]).map_err(|_| {
                ModernEventError::new(crate::modern_event::ErrorType::InvalidHeader)
            })?)
        } else {
            None
        };
        let event_id = if used_flags.contains(UsedFliedsFlags::EventID) {
            Some(u16_from_le_slice(&buf[48..50])?)
        } else {
            None
        };
        let event_version = if used_flags.contains(UsedFliedsFlags::EventVersion) {
            Some(buf[50])
        } else {
            None
        };
        let event_channel = if used_flags.contains(UsedFliedsFlags::EventChannel) {
            Some(buf[51])
        } else {
            None
        };
        let event_level = if used_flags.contains(UsedFliedsFlags::EventLevel) {
            Some(buf[52])
        } else {
            None
        };
        let event_opcode = if used_flags.contains(UsedFliedsFlags::EventOpcode) {
            Some(buf[53])
        } else {
            None
        };
        let event_task = if used_flags.contains(UsedFliedsFlags::EventTask) {
            Some(u16_from_le_slice(&buf[54..56])?)
        } else {
            None
        };
        let event_keywords = if used_flags.contains(UsedFliedsFlags::EventKeywords) {
            Some(u64_from_le_slice(&buf[56..64])?)
        } else {
            None
        };
        let thread_id = if used_flags.contains(UsedFliedsFlags::ThreadId) {
            Some(u64_from_le_slice(&buf[64..72])?)
        } else {
            None
        };
        let process_id = if used_flags.contains(UsedFliedsFlags::ProcessID) {
            Some(u64_from_le_slice(&buf[72..80])?)
        } else {
            None
        };
        let parent_process_id = if used_flags.contains(UsedFliedsFlags::ParentProcessID) {
            Some(u64_from_le_slice(&buf[80..88])?)
        } else {
            None
        };
        let cpu_id = if used_flags.contains(UsedFliedsFlags::CpuID) {
            Some(u32_from_le_slice(&buf[88..92])?)
        } else {
            None
        };
        let irql = if used_flags.contains(UsedFliedsFlags::Irql) {
            Some(buf[92])
        } else {
            None
        };
        let payload_size = if used_flags.contains(UsedFliedsFlags::Payload) {
            Some(u16_from_le_slice(&buf[94..96])?)
        } else {
            None
        };

        Ok(XED2EventHeader {
            size,
            header_size,
            extraction_method,
            used_flags,
            written_event_count,
            captured_event_count,
            timestamp,
            provider_id,
            event_id,
            event_version,
            event_channel,
            event_level,
            event_opcode,
            event_task,
            event_keywords,
            thread_id,
            process_id,
            parent_process_id,
            cpu_id,
            irql,
            payload_size,
        })
    }
}

/// Method the event was extracted with
#[repr(u8)]
#[non_exhaustive]
#[derive(Debug, Clone, Copy, TryFromPrimitive)]
pub enum ExtractionMethod {
    None = 0,
    /// 64 Bit Kernel Mode `nt!EtwWriteEx` function
    KMEtwWriteEx64 = 1,
    /// 64 Bit User Mode `ntdll!EtwpEventWriteFull` function
    UMEtwpEventWriteFull64 = 2
}

bitflags! {
    /// Used header fields
    ///
    /// Indicate which fields of a [XED2Event] are present.
    /// Not all fields of a [XED2Event] and [XED2EventHeader] might be set,
    /// depending on event type and general conditions under which the event was captured.
    #[derive(Debug, Clone, Copy, Serialize)]
    pub struct UsedFliedsFlags: u16 {
        const ProviderClassGUID = 0b0000_0000_0000_0001;
        const EventID = 0b0000_0000_0000_0010;
        const EventVersion = 0b0000_0000_0000_0100;
        const EventChannel = 0b0000_0000_0000_1000;
        const EventLevel = 0b0000_0000_0001_0000;
        const EventOpcode = 0b0000_0000_0010_0000;
        const EventTask = 0b0000_0000_0100_0000;
        const EventKeywords = 0b0000_0000_1000_0000;
        const CpuID = 0b0000_0001_0000_0000;
        const Irql = 0b0000_0010_0000_0000;
        const ThreadId = 0b0000_0100_0000_0000;
        const ProcessID = 0b0000_1000_0000_0000;
        const ParentProcessID = 0b0001_0000_0000_0000;
        const ProcessName = 0b0010_0000_0000_0000;
        const ExePathName = 0b0100_0000_0000_0000;
        const Payload = 0b1000_0000_0000_0000;
    }
}

// impl From<XED2Event> for super::ModernEvent {
//     fn from(value: XED2Event) -> Self {
//         let header = super::ModernEventHeader {
//             size: value.header.size,
//             header_type: crate::TraceHeaderType::ModernEvent64,
//             flags: 0,
//             event_flags: super::Flags::empty(),
//             event_properties: 0,
//             thread_id: value.header.thread_id.unwrap_or_default() as u32, // TODO u64 or u32 whats correct?
//             process_id: value.header.process_id.unwrap_or_default() as u32,
//             timestamp: EtwTimestamp::default(),
//             provider_id: value.header.provider_id.unwrap_or_default(),
//             event_descriptor: (&value.header).into(),
//             time_union: value.header.timestamp,
//             activity_id: Uuid::default(),
//         };
//         super::ModernEvent {
//             header,
//             extended_header: None,
//             payload: Cursor::new(value.payload.unwrap_or_default()),
//         }
//     }
// }

impl TryFrom<&XED2EventHeader> for super::EventDescriptor {
    type Error = ModernEventError;
    fn try_from(value: &XED2EventHeader) -> Result<Self, Self::Error> {
        use super::ErrorType::NotSupported;
        Ok(super::EventDescriptor {
            id: value
                .event_id
                .ok_or(ModernEventError::new_with_description(
                    NotSupported,
                    "XED2 header has no event-id set",
                ))?,
            version: value
                .event_version
                .ok_or(ModernEventError::new_with_description(
                    NotSupported,
                    "XED2 header has no event version set",
                ))?,
            channel: value
                .event_channel
                .ok_or(ModernEventError::new_with_description(
                    NotSupported,
                    "XED2 header has no event channel set",
                ))?,
            level: value
                .event_level
                .ok_or(ModernEventError::new_with_description(
                    NotSupported,
                    "XED2 header has no event level set",
                ))?,
            opcode: value
                .event_opcode
                .ok_or(ModernEventError::new_with_description(
                    NotSupported,
                    "XED2 header has no event opcode set",
                ))?,
            task: value
                .event_task
                .ok_or(ModernEventError::new_with_description(
                    NotSupported,
                    "XED2 header has no event task set",
                ))?,
            keywords: value
                .event_keywords
                .ok_or(ModernEventError::new_with_description(
                    NotSupported,
                    "XED2 header has no event keywords set",
                ))?,
        })
    }
}

impl TryFrom<XED2Event> for super::ModernEvent {
    type Error = ModernEventError;

    fn try_from(value: XED2Event) -> Result<Self, Self::Error> {
        use super::ErrorType;
        let header = super::ModernEventHeader {
            size: value.header.size,
            header_type: crate::TraceHeaderType::ModernEvent64,
            flags: 0,
            event_flags: super::Flags::empty(),
            event_properties: 0,
            thread_id: value.header.thread_id.unwrap_or_default() as u32, // TODO u64 or u32 whats correct?
            process_id: value.header.process_id.unwrap_or_default() as u32,
            timestamp: EtwTimestamp::default(),
            provider_id: value
                .header
                .provider_id
                .ok_or(ModernEventError::new_with_description(
                    ErrorType::NotSupported,
                    "XED2 event has no provider id set (required to convert into ModernEvent)",
                ))?,
            event_descriptor: (&value.header).try_into()?,
            time_union: value.header.timestamp,
            activity_id: Uuid::default(),
        };
        Ok(super::ModernEvent {
            header,
            extended_header: None,
            payload: Cursor::new(value.payload.unwrap_or_default()),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use crate::modern_event::ModernEvent;

    use super::XED2Event;

    const XED2_EXAMPLE: &[u8] = include_bytes!("etw.xed2");

    #[test]
    fn xed2_from_slice() {
        let xed2_event = XED2Event::parse_slice(XED2_EXAMPLE);
        assert!(xed2_event.is_ok());

        let xed2_event = xed2_event.unwrap();

        let modern_event: ModernEvent = xed2_event.try_into().unwrap();

        let mut event = modern_event.into_contained_event().unwrap();

        println!("{}", event.get_provider_name());
        println!("{:?}", event.get_event_task_name());
        println!("{:#?}", event.get_payload_items());
    }

    #[test]
    fn xed2_from_reader() {
        let mut reader = Cursor::new(XED2_EXAMPLE);
        let xed2_event = XED2Event::parse(&mut reader);
        assert!(xed2_event.is_ok());

        let xed2_event = xed2_event.unwrap();

        let modern_event: ModernEvent = xed2_event.try_into().unwrap();

        let mut event = modern_event.into_contained_event().unwrap();

        println!("{}", event.get_provider_name());
        println!("{:?}", event.get_event_task_name());
        println!("{:#?}", event.get_payload_items());
    }
}

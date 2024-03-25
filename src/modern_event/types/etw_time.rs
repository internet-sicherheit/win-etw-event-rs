use crate::types::FileTime;

/// Container for ETW timestamps
///
/// Holds either [EtwTime] or a [FileTime].
/// A [EtwTime] can be converted to a [FileTime] in place by supplying a scale and time base.
#[derive(Debug, Clone, Copy)]
pub enum EtwTimestamp {
    EtwTime(EtwTime),
    Filetime(FileTime),
}

/// Time format used in modern event headers
///
/// Format with no fix time base and scale dependent of etw session and system configuration.
/// Other than timestamps in event payloads, the timestamp present in a modern event header
/// has no fixed scale and time base and must always be converted to a other format.
/// Can be converted to a [FileTime] by providing a time base and scale.
#[derive(Debug, Clone, Copy)]
pub struct EtwTime(pub u64);

impl EtwTime {
    /// Convert a [EtwTime] to a [FileTime]
    ///
    /// The scale and time base are usually session dependent and can be obtained from the trace logfile header and wmi buffer header.
    pub fn into_filetime(self, timestamp_scale: f64, timestamp_base: u64) -> FileTime {
        FileTime::from_i64(timestamp_base as i64 + (timestamp_scale * self.0 as f64) as i64)
    }
}

impl EtwTimestamp {
    /// Convert a [EtwTime] variant to a [FileTime] variant returning a ref to the [FileTime]
    ///
    /// When the Timestamp already holds a [FileTime] this is a no-op,
    /// otherwise the [EtwTime] is converted using the supplied scale and base.
    pub fn to_filetime(&mut self, timestamp_scale: f64, timestamp_base: u64) -> &FileTime {
        match self {
            EtwTimestamp::EtwTime(etw_time) => {
                *self =
                    EtwTimestamp::Filetime(etw_time.into_filetime(timestamp_scale, timestamp_base));
                match self {
                    EtwTimestamp::EtwTime(_) => unreachable!(),
                    EtwTimestamp::Filetime(f) => f,
                }
            }
            EtwTimestamp::Filetime(time) => time,
        }
    }
}

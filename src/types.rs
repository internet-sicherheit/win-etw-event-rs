//! Datatypes uesd by ETW

pub use filetime_type::FileTime;

use std::{error::Error, fmt::Display, io::Read};

use byteorder::{ByteOrder, LittleEndian};
use chrono::{offset::Utc, DateTime, TimeZone};

#[derive(Debug)]
pub enum SystemTimeParseError {
    ReadError(std::io::Error),
    InvalidDayOfWeek,
    InvalidYear,
    InvalidMonth,
    InvalidDay,
    InvalidHour,
    InvalidMinute,
    InvalidSecond,
    InvalidMillisecond,
}
impl Display for SystemTimeParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "An error occured while trying to parse a SYSTEMTIME.")
    }
}
impl Error for SystemTimeParseError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            SystemTimeParseError::ReadError(e) => Some(e),
            _ => None,
        }
    }
}
impl From<std::io::Error> for SystemTimeParseError {
    fn from(value: std::io::Error) -> Self {
        SystemTimeParseError::ReadError(value)
    }
}
impl From<DayOfWeekParseError> for SystemTimeParseError {
    fn from(_value: DayOfWeekParseError) -> Self {
        SystemTimeParseError::InvalidDayOfWeek
    }
}

/// Windows SYSTEMTIME type
///
/// For further information refer to the [Microsoft Windows Documentation](https://learn.microsoft.com/en-us/windows/win32/api/minwinbase/ns-minwinbase-systemtime).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SystemTime {
    w_year: u16,
    w_month: u16,
    w_day_of_week: DayOfWeek,
    w_day: u16,
    w_hour: u16,
    w_minute: u16,
    w_second: u16,
    w_milliseconds: u16,
}
impl SystemTime {
    /// Read 16 bytes from a [Reader](Read) to parse a [SystemTime]
    pub fn parse<T: Read>(r: &mut T) -> Result<Self, SystemTimeParseError> {
        let mut buf = [0_u8; 16];
        r.read_exact(&mut buf)?;
        Self::try_from(buf)
    }
    pub fn year(&self) -> u16 {
        self.w_year
    }
    pub fn month(&self) -> u16 {
        self.w_month
    }
    pub fn day_of_week(&self) -> DayOfWeek {
        self.w_day_of_week
    }
    pub fn day(&self) -> u16 {
        self.w_day
    }
    pub fn hour(&self) -> u16 {
        self.w_hour
    }
    pub fn minute(&self) -> u16 {
        self.w_minute
    }
    pub fn second(&self) -> u16 {
        self.w_second
    }
    pub fn millisecond(&self) -> u16 {
        self.w_milliseconds
    }
    /// Create a UTC DateTime
    pub fn to_datetime(&self) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(
            self.year() as i32,
            self.month() as u32,
            self.day() as u32,
            self.hour() as u32,
            self.minute() as u32,
            self.second() as u32,
        )
        .unwrap()
    }
}
impl TryFrom<[u8; 16]> for SystemTime {
    type Error = SystemTimeParseError;

    fn try_from(value: [u8; 16]) -> Result<Self, Self::Error> {
        let mut u16_buf = [0_u16; 8];
        LittleEndian::read_u16_into(&value, &mut u16_buf);

        let w_year = u16_buf[0];
        let w_month = u16_buf[1];
        let w_day_of_week: DayOfWeek = u16_buf[2].try_into()?;
        let w_day = u16_buf[3];
        let w_hour = u16_buf[4];
        let w_minute = u16_buf[5];
        let w_second = u16_buf[6];
        let w_milliseconds = u16_buf[7];

        if !(1601..=30827).contains(&w_year) {
            return Err(SystemTimeParseError::InvalidYear);
        }
        if !(1..=12).contains(&w_month) {
            return Err(SystemTimeParseError::InvalidMonth);
        }
        if !(1..=31).contains(&w_day) {
            return Err(SystemTimeParseError::InvalidDay);
        }
        if !(0..=23).contains(&w_hour) {
            return Err(SystemTimeParseError::InvalidHour);
        }
        if !(0..=59).contains(&w_minute) {
            return Err(SystemTimeParseError::InvalidMinute);
        }
        if !(0..=59).contains(&w_second) {
            return Err(SystemTimeParseError::InvalidSecond);
        }
        if !(0..=999).contains(&w_milliseconds) {
            return Err(SystemTimeParseError::InvalidSecond);
        }

        Ok(SystemTime {
            w_year,
            w_month,
            w_day_of_week,
            w_day,
            w_hour,
            w_minute,
            w_second,
            w_milliseconds,
        })
    }
}

impl serde::Serialize for SystemTime {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.to_datetime().serialize(serializer)
    }
}

impl Display for SystemTime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} {:02}.{:02}.{:04} {:02}:{:02}:{:02}'{:03}",
            self.w_day_of_week,
            self.w_day,
            self.w_month,
            self.w_year,
            self.w_hour,
            self.w_minute,
            self.w_second,
            self.w_milliseconds
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DayOfWeek {
    Sunday,
    Monday,
    Tuesday,
    Wednesday,
    Thursday,
    Friday,
    Saturday,
}
impl Display for DayOfWeek {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DayOfWeek::Sunday => write!(f, "Su"),
            DayOfWeek::Monday => write!(f, "Mo"),
            DayOfWeek::Tuesday => write!(f, "Tu"),
            DayOfWeek::Wednesday => write!(f, "We"),
            DayOfWeek::Thursday => write!(f, "Th"),
            DayOfWeek::Friday => write!(f, "Fr"),
            DayOfWeek::Saturday => write!(f, "Sa"),
        }
    }
}
#[derive(Debug, Clone, Copy)]
pub struct DayOfWeekParseError;
impl TryFrom<u16> for DayOfWeek {
    type Error = DayOfWeekParseError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(DayOfWeek::Sunday),
            1 => Ok(DayOfWeek::Monday),
            2 => Ok(DayOfWeek::Tuesday),
            3 => Ok(DayOfWeek::Wednesday),
            4 => Ok(DayOfWeek::Thursday),
            5 => Ok(DayOfWeek::Friday),
            6 => Ok(DayOfWeek::Saturday),
            _ => Err(DayOfWeekParseError),
        }
    }
}

#[cfg(test)]
mod tests {

    use std::io::Cursor;

    use super::SystemTime;

    #[test]
    fn display_systemtime() {
        let timestamp = SystemTime {
            w_year: 2024,
            w_month: 2,
            w_day_of_week: super::DayOfWeek::Monday,
            w_day: 19,
            w_hour: 18,
            w_minute: 1,
            w_second: 00,
            w_milliseconds: 42,
        };

        assert_eq!(timestamp.to_string(), "Mo 19.02.2024 18:01:00'042");
    }

    #[test]
    fn parse_systemtime() {
        let mut buf: Vec<u8> = Vec::with_capacity(16);
        buf.extend_from_slice(&2024_u16.to_le_bytes()); // Year
        buf.extend_from_slice(&2_u16.to_le_bytes()); // Month
        buf.extend_from_slice(&1_u16.to_le_bytes()); // Day of month
        buf.extend_from_slice(&19_u16.to_le_bytes()); // Day

        buf.extend_from_slice(&18_u16.to_le_bytes()); // Hour
        buf.extend_from_slice(&1_u16.to_le_bytes()); // Minute
        buf.extend_from_slice(&00_u16.to_le_bytes()); // Second
        buf.extend_from_slice(&42_u16.to_le_bytes()); // Millisecond

        let buf_len = buf.len();
        let mut cursor = Cursor::new(buf);
        let timestamp = SystemTime::parse(&mut cursor).expect("Error parsing SYSTEMTIME from buf!");

        let expected = SystemTime {
            w_year: 2024,
            w_month: 2,
            w_day_of_week: super::DayOfWeek::Monday,
            w_day: 19,
            w_hour: 18,
            w_minute: 1,
            w_second: 00,
            w_milliseconds: 42,
        };
        assert_eq!(timestamp, expected);
        assert_eq!(cursor.position(), buf_len as u64);
    }
}

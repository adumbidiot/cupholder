use std::convert::TryFrom;
use std::convert::TryInto;
use winapi::shared::minwindef::DWORD;
use winapi::shared::minwindef::UINT;
use winapi::um::fileapi::CreateFileW;
use winapi::um::fileapi::GetDriveTypeW;
use winapi::um::fileapi::GetLogicalDrives;
use winapi::um::fileapi::OPEN_EXISTING;
use winapi::um::handleapi::INVALID_HANDLE_VALUE;
use winapi::um::ioapiset::DeviceIoControl;
use winapi::um::winbase::DRIVE_CDROM;
use winapi::um::winbase::DRIVE_FIXED;
use winapi::um::winbase::DRIVE_NO_ROOT_DIR;
use winapi::um::winbase::DRIVE_RAMDISK;
use winapi::um::winbase::DRIVE_REMOTE;
use winapi::um::winbase::DRIVE_REMOVABLE;
use winapi::um::winbase::DRIVE_UNKNOWN;
use winapi::um::winioctl::IOCTL_STORAGE_EJECT_MEDIA;
use winapi::um::winnt::FILE_ATTRIBUTE_READONLY;
use winapi::um::winnt::FILE_SHARE_READ;
use winapi::um::winnt::FILE_SHARE_WRITE;
use winapi::um::winnt::GENERIC_READ;

bitflags::bitflags! {
    pub struct LogicalDrives: DWORD {
        const A = 0x01 << 0;
        const B = 0x01 << 1;
        const C = 0x01 << 2;
        const D = 0x01 << 3;
        const E = 0x01 << 4;
        const F = 0x01 << 5;
        const G = 0x01 << 6;
        const H = 0x01 << 7;
        const I = 0x01 << 8;
        const J = 0x01 << 9;
        const K = 0x01 << 10;
        const L = 0x01 << 11;
        const M = 0x01 << 12;
        const N = 0x01 << 13;
        const O = 0x01 << 14;
        const P = 0x01 << 15;
        const Q = 0x01 << 16;
        const R = 0x01 << 17;
        const S = 0x01 << 18;
        const T = 0x01 << 19;
        const U = 0x01 << 20;
        const V = 0x01 << 21;
        const W = 0x01 << 22;
        const X = 0x01 << 23;
        const Y = 0x01 << 24;
        const Z = 0x01 << 25;
    }
}

impl LogicalDrives {
    /// Get the number of logical drives
    pub fn count(&self) -> u32 {
        self.bits().count_ones()
    }

    /// Get the drives as ascii letters
    pub fn iter_letters(&self) -> impl Iterator<Item = u8> {
        let mut i = 0;
        let flag = *self;
        std::iter::from_fn(move || loop {
            let test_flag = Self::from_bits(0x01 << i)?;
            let drive_letter = b'A' + i;
            i += 1;
            if flag.contains(test_flag) {
                return Some(drive_letter);
            }
        })
    }
}

/// Get the logical drives
pub fn get_logical_drives() -> std::io::Result<LogicalDrives> {
    let ret = unsafe { GetLogicalDrives() };
    if ret == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(LogicalDrives::from_bits(ret).expect("invalid logical drives state"))
}

/// Drive Types
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum DriveType {
    Unknown,
    NoRootDir,
    Removable,
    Fixed,
    Remote,
    CdRom,
    RamDisk,
}

impl DriveType {
    /// Check if this is a cd rom
    pub fn is_cd_rom(self) -> bool {
        matches!(self, Self::CdRom)
    }
}

impl TryFrom<UINT> for DriveType {
    type Error = UINT;
    fn try_from(data: UINT) -> Result<Self, Self::Error> {
        match data {
            DRIVE_UNKNOWN => Ok(Self::Unknown),
            DRIVE_NO_ROOT_DIR => Ok(Self::NoRootDir),
            DRIVE_REMOVABLE => Ok(Self::Removable),
            DRIVE_FIXED => Ok(Self::Fixed),
            DRIVE_REMOTE => Ok(Self::Remote),
            DRIVE_CDROM => Ok(Self::CdRom),
            DRIVE_RAMDISK => Ok(Self::RamDisk),
            _ => Err(data),
        }
    }
}

/// Get the drive type
pub fn get_drive_type(drive_letter: u8) -> DriveType {
    let drive_str = [
        u16::from(drive_letter),
        u16::from(b':'),
        u16::from(b'\\'),
        0,
    ];
    let ret = unsafe { GetDriveTypeW(drive_str.as_ptr()) };
    ret.try_into().expect("invalid drive type")
}

pub struct CdDrive(skylight::Handle);

impl CdDrive {
    pub fn new(drive_letter: u8) -> std::io::Result<Self> {
        let drive_str = [
            u16::from(b'\\'),
            u16::from(b'\\'),
            u16::from(b'.'),
            u16::from(b'\\'),
            u16::from(drive_letter),
            u16::from(b':'),
            0,
        ];
        let handle = unsafe {
            CreateFileW(
                drive_str.as_ptr(),
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                std::ptr::null_mut(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_READONLY,
                std::ptr::null_mut(),
            )
        };

        if handle == INVALID_HANDLE_VALUE {
            return Err(std::io::Error::last_os_error());
        }

        let handle = unsafe { skylight::Handle::from_raw(handle.cast()) };

        Ok(Self(handle))
    }

    pub fn eject(&self) -> std::io::Result<()> {
        let mut bytes_returned = 0;
        let ret = unsafe {
            DeviceIoControl(
                self.0.as_raw().cast(),
                IOCTL_STORAGE_EJECT_MEDIA,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                0,
                &mut bytes_returned,
                std::ptr::null_mut(),
            )
        };

        if ret == 0 {
            return Err(std::io::Error::last_os_error());
        }

        Ok(())
    }
}

fn main() {
    println!("Scanning for installed cupholders...");
    let drives = get_logical_drives().expect("failed to get logical drives");
    let cd_roms = drives
        .iter_letters()
        .filter(|drive| get_drive_type(*drive).is_cd_rom())
        .collect::<Vec<_>>();

    if cd_roms.is_empty() {
        println!("Your computer does not support cupholders :(");
    } else {
        println!(
            "Located {} cupholder(s) installed on your system!",
            cd_roms.len()
        );
        println!("Activating cupholders...");

        for letter in cd_roms {
            let drive = CdDrive::new(letter).expect("failed to open cd drive");
            drive.eject().expect("failed to eject");
        }
    }

    let _ = std::process::Command::new("cmd.exe")
        .arg("/c")
        .arg("pause")
        .status();
}

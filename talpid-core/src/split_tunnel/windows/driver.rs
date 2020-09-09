use super::windows::get_final_path_name;
use std::{
    ffi::OsStr,
    fs::{self, OpenOptions},
    io,
    mem::{self, size_of},
    os::windows::{
        ffi::OsStrExt,
        fs::OpenOptionsExt,
        io::{AsRawHandle, RawHandle},
    },
    ptr,
};
use winapi::um::{
    ioapiset::DeviceIoControl,
    winioctl::{FILE_ANY_ACCESS, METHOD_BUFFERED, METHOD_NEITHER},
};

const DRIVER_SYMBOLIC_NAME: &str = "\\\\.\\MULLVADSPLITTUNNEL";
const ST_DEVICE_TYPE: u32 = 0x8000;

const fn ctl_code(device_type: u32, function: u32, method: u32, access: u32) -> u32 {
    device_type << 16 | access << 14 | function << 2 | method
}

#[repr(u32)]
#[allow(dead_code)]
enum DriverIoctlCode {
    Initialize = ctl_code(ST_DEVICE_TYPE, 1, METHOD_NEITHER, FILE_ANY_ACCESS),
    DequeEvent = ctl_code(ST_DEVICE_TYPE, 2, METHOD_BUFFERED, FILE_ANY_ACCESS),
    RegisterProcesses = ctl_code(ST_DEVICE_TYPE, 3, METHOD_BUFFERED, FILE_ANY_ACCESS),
    RegisterIpAddresses = ctl_code(ST_DEVICE_TYPE, 4, METHOD_BUFFERED, FILE_ANY_ACCESS),
    GetIpAddresses = ctl_code(ST_DEVICE_TYPE, 5, METHOD_BUFFERED, FILE_ANY_ACCESS),
    SetConfiguration = ctl_code(ST_DEVICE_TYPE, 6, METHOD_BUFFERED, FILE_ANY_ACCESS),
    GetConfiguration = ctl_code(ST_DEVICE_TYPE, 7, METHOD_BUFFERED, FILE_ANY_ACCESS),
    ClearConfiguration = ctl_code(ST_DEVICE_TYPE, 8, METHOD_NEITHER, FILE_ANY_ACCESS),
    GetState = ctl_code(ST_DEVICE_TYPE, 9, METHOD_BUFFERED, FILE_ANY_ACCESS),
    QueryProcess = ctl_code(ST_DEVICE_TYPE, 10, METHOD_BUFFERED, FILE_ANY_ACCESS),
}

#[derive(Debug, PartialEq)]
#[repr(u32)]
#[allow(dead_code)]
pub enum DriverState {
    // Default state after being loaded.
    None = 0,
    // DriverEntry has completed successfully.
    // Basically only driver and device objects are created at this point.
    Started = 1,
    // All subsystems are initialized.
    Initialized = 2,
    // User mode has registered all processes in the system.
    Ready = 3,
    // IP addresses are registered.
    // A valid configuration is registered.
    Engaged = 4,
    // Driver is unloading.
    Terminating = 5,
}

pub struct DeviceHandle {
    handle: fs::File,
}

impl DeviceHandle {
    pub fn new() -> io::Result<Self> {
        // Connect to the driver
        let handle = OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(0)
            .custom_flags(0)
            .attributes(0)
            .open(DRIVER_SYMBOLIC_NAME)?;

        let device = Self { handle };

        // Initialize the driver

        let state = device.get_driver_state()?;
        if state == DriverState::Started {
            device.initialize()?;
        }

        Ok(device)
    }

    fn initialize(&self) -> io::Result<()> {
        device_io_control(
            self.handle.as_raw_handle(),
            DriverIoctlCode::Initialize as u32,
            None,
            0,
        )?;
        Ok(())
    }

    pub fn get_driver_state(&self) -> io::Result<DriverState> {
        let buffer = device_io_control(
            self.handle.as_raw_handle(),
            DriverIoctlCode::GetState as u32,
            None,
            size_of::<u64>() as u32,
        )?
        .unwrap();

        Ok(unsafe { deserialize_buffer(&buffer) })
    }

    pub fn set_config<T: AsRef<OsStr>>(&self, apps: &[T]) -> io::Result<()> {
        let mut device_paths = Vec::with_capacity(apps.len());
        for app in apps.as_ref() {
            device_paths.push(get_final_path_name(app)?);
        }
        let config = make_process_config(&device_paths);

        device_io_control(
            self.handle.as_raw_handle(),
            DriverIoctlCode::SetConfiguration as u32,
            Some(&config),
            0,
        )?;

        Ok(())
    }
}

#[repr(C)]
struct ConfigurationHeader {
    // Number of entries immediately following the header.
    num_entries: usize,
    // Total byte length: header + entries + string buffer.
    total_length: usize,
}

#[repr(C)]
struct ConfigurationEntry {
    // Offset into buffer region that follows all entries.
    // The image name uses the physical path.
    name_offset: usize,
    // Byte length for non-null terminated wide char string.
    name_length: u16,
}

/// Create a buffer containing information.
/// This consists of a header and number of entries, followed by the same number of strings.
fn make_process_config<T: AsRef<OsStr>>(apps: &[T]) -> Vec<u8> {
    // TODO: possible without copying?
    let apps: Vec<Vec<u16>> = apps
        .iter()
        .map(|app| app.as_ref().encode_wide().collect())
        .collect();

    let total_string_size: usize = apps.iter().map(|app| size_of::<u16>() * app.len()).sum();

    let total_buffer_size = size_of::<ConfigurationHeader>()
        + size_of::<ConfigurationEntry>() * apps.len()
        + total_string_size;

    let mut buffer = Vec::<u8>::new();
    buffer.resize(total_buffer_size, 0);

    // Serialize configuration header
    let header = ConfigurationHeader {
        num_entries: apps.len(),
        total_length: total_buffer_size,
    };
    unsafe {
        ptr::copy_nonoverlapping(
            &header as *const _ as *const u8,
            buffer.as_mut_ptr(),
            size_of::<ConfigurationHeader>(),
        )
    };

    // Serialize configuration entries and strings
    let mut entries = unsafe {
        std::slice::from_raw_parts_mut(
            &mut buffer[size_of::<ConfigurationHeader>()..] as *mut _ as *mut ConfigurationEntry,
            apps.len(),
        )
    };
    let string_data = unsafe {
        std::slice::from_raw_parts_mut(
            &mut buffer[(total_buffer_size - total_string_size)..] as *mut _ as *mut u16,
            total_string_size / size_of::<u16>(),
        )
    };
    let mut string_offset = 0;

    for (i, app) in apps.iter().enumerate() {
        string_data[string_offset..string_offset + app.len()].copy_from_slice(app);

        entries[i].name_offset = string_offset * size_of::<u16>();
        entries[i].name_length = (app.len() * size_of::<u16>()) as u16;

        string_offset += app.len();
    }

    buffer
}

/// Send an IOCTL code to the given device handle.
/// `input` specifies an optional buffer to send.
/// Upon success, a buffer of size `output_size` is returned, or None if `output_size` is 0.
pub fn device_io_control(
    device: RawHandle,
    ioctl_code: u32,
    input: Option<&[u8]>,
    output_size: u32,
) -> Result<Option<Vec<u8>>, io::Error> {
    let input_ptr = match input {
        Some(input) => input as *const _ as *mut _,
        None => ptr::null_mut(),
    };
    let input_len = input.map(|input| input.len()).unwrap_or(0);

    let mut out_buffer = if output_size > 0 {
        Some(Vec::with_capacity(output_size as usize))
    } else {
        None
    };

    let out_ptr = match out_buffer {
        Some(ref mut out_buffer) => out_buffer.as_mut_ptr() as *mut _,
        None => ptr::null_mut(),
    };

    let mut returned_bytes = 0u32;

    let result = unsafe {
        DeviceIoControl(
            device as *mut _,
            ioctl_code,
            input_ptr,
            input_len as u32,
            out_ptr,
            output_size,
            &mut returned_bytes as *mut _,
            ptr::null_mut(), // TODO
        )
    };

    if let Some(ref mut out_buffer) = out_buffer {
        unsafe { out_buffer.set_len(returned_bytes as usize) };
    }

    if result != 0 {
        Ok(out_buffer)
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Creates a new instance of an arbitrary type from a byte buffer.
pub unsafe fn deserialize_buffer<T: Sized>(buffer: &Vec<u8>) -> T {
    let mut instance: T = mem::zeroed();
    ptr::copy_nonoverlapping(buffer.as_ptr() as *const T, &mut instance as *mut _, 1);
    instance
}

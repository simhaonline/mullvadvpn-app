use std::{
    io, mem,
    os::windows::{ffi::OsStringExt, io::RawHandle},
    ptr,
};
use winapi::um::ioapiset::DeviceIoControl;

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

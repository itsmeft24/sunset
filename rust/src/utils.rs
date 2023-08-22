use windows_sys::Win32::System::Memory::*;

#[repr(u32)]
pub enum Perm {
    None = PAGE_NOACCESS,
    Read = PAGE_READONLY,
    ReadWrite = PAGE_READWRITE,
    WriteCopy = PAGE_WRITECOPY,
    Execute = PAGE_EXECUTE,
    ExecuteRead = PAGE_EXECUTE_READ,
    ExecuteReadWrite = PAGE_EXECUTE_READWRITE,
    ExecuteWriteCopy = PAGE_EXECUTE_WRITECOPY,
    Guard = PAGE_GUARD,
    NoCache = PAGE_NOCACHE,
    WriteCombine = PAGE_WRITECOMBINE,
}

// Sets the desired permission on the memory block.
pub unsafe fn set_permission(ptr: *mut u8, size: usize, perm: Perm) -> Option<Perm> {
    let mut old_perm: Perm = Perm::None;
    let success = unsafe {
        VirtualProtect(
            std::mem::transmute(ptr),
            size,
            perm as PAGE_PROTECTION_FLAGS,
            std::mem::transmute(&mut old_perm),
        )
    };
    if success != 0 {
        Some(old_perm)
    } else {
        None
    }
}

pub struct JitMemory<'a> {
	pub data: &'a mut [u8],
}

impl<'a> JitMemory<'a> {
	pub fn new(size: usize) -> Self {
		let data = unsafe {
			let ptr = VirtualAlloc(
				std::ptr::null_mut(),
				size,
				MEM_COMMIT | MEM_RESERVE,
				PAGE_EXECUTE_READWRITE,
			) as *mut u8;
			std::slice::from_raw_parts_mut(ptr, size)
		};
		Self {
			data,
		}
	}
}

impl<'a> std::ops::Drop for JitMemory<'a> {
	fn drop(&mut self) {
		unsafe {
			VirtualFree(self.data.as_mut_ptr() as *mut core::ffi::c_void, 0, MEM_RELEASE)
		};
	}
}

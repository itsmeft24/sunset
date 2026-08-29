use std::{mem::MaybeUninit, os::raw::c_void};

use windows_sys::Win32::System::{
    LibraryLoader::GetModuleHandleA,
    Memory::*,
    SystemInformation::{GetSystemInfo, SYSTEM_INFO},
    Threading::GetCurrentProcess,
};

#[repr(u32)]
pub enum Access {
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
pub unsafe fn set_permission(ptr: *mut (), size: usize, access: Access) -> Option<Access> {
    let mut old_access: Access = Access::None;
    let success = unsafe {
        VirtualProtect(
            std::mem::transmute(ptr),
            size,
            access as PAGE_PROTECTION_FLAGS,
            std::mem::transmute(&mut old_access),
        )
    };
    if success != 0 {
        Some(old_access)
    } else {
        None
    }
}

pub fn get_main_load_address() -> usize {
    unsafe { GetModuleHandleA(std::ptr::null()) as usize }
}

pub struct JitMemory<'a> {
    pub data: &'a mut [u8],
}

impl<'a> JitMemory<'a> {
    pub fn new(size: usize) -> Self {
        let data = unsafe {
            let ptr = VirtualAlloc(
                std::ptr::null(),
                size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            ) as *mut u8;
            std::slice::from_raw_parts_mut(ptr, size)
        };
        Self { data }
    }
    pub unsafe fn new_placement(address: usize, size: usize) -> Option<Self> {
        let ptr = VirtualAlloc(
            address as *const c_void,
            size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        ) as *mut u8;
        if ptr.is_null() {
            return None;
        }
        Some(Self {
            data: std::slice::from_raw_parts_mut(ptr, size),
        })
    }
}

impl<'a> std::ops::Drop for JitMemory<'a> {
    fn drop(&mut self) {
        unsafe {
            VirtualFree(
                self.data.as_mut_ptr() as *mut core::ffi::c_void,
                0,
                MEM_RELEASE,
            )
        };
    }
}

pub unsafe fn allocate_near(
    address: usize,
    len: usize,
    max_distance: usize,
) -> Option<JitMemory<'static>> {
    let mut info_uninit: MaybeUninit<SYSTEM_INFO> = MaybeUninit::zeroed();
    GetSystemInfo(info_uninit.as_mut_ptr());
    let info = info_uninit.assume_init();

    let aligned_address = address & !(info.dwAllocationGranularity as usize - 1);

    // Iterate backwards towards the start of the available address space from the given `address` argument.
    let mut current_address = aligned_address;
    while current_address > info.lpMinimumApplicationAddress as usize
        && current_address.abs_diff(address) < max_distance
    {
        let mut mbi_uninit: MaybeUninit<MEMORY_BASIC_INFORMATION> = MaybeUninit::zeroed();
        VirtualQueryEx(
            GetCurrentProcess(),
            current_address as *const c_void,
            mbi_uninit.as_mut_ptr(),
            std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
        );
        let mbi = mbi_uninit.assume_init();
        if mbi.State == MEM_FREE {
            if let Some(block) = JitMemory::new_placement(current_address, len) {
                return Some(block);
            }
        }
        current_address -= info.dwAllocationGranularity as usize;
    }

    // Iterate forwards towards the end of the available address space from the given `address` argument.
    current_address = aligned_address;
    while current_address < info.lpMaximumApplicationAddress as usize
        && current_address.abs_diff(address) < max_distance
    {
        let mut mbi_uninit: MaybeUninit<MEMORY_BASIC_INFORMATION> = MaybeUninit::zeroed();
        VirtualQueryEx(
            GetCurrentProcess(),
            current_address as *const c_void,
            mbi_uninit.as_mut_ptr(),
            std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
        );
        let mbi = mbi_uninit.assume_init();
        if mbi.State == MEM_FREE {
            if let Some(block) = JitMemory::new_placement(current_address, len) {
                return Some(block);
            }
        }
        current_address += info.dwAllocationGranularity as usize;
    }

    return None;
}

pub unsafe fn write_data(dst: *mut u8, bytes: &[u8]) {
    std::slice::from_raw_parts_mut(dst, bytes.len()).copy_from_slice(bytes);
}

use std::sync::Mutex;

use once_cell::sync::Lazy;
use utils::JitMemory;
use windows_sys::Win32::System::Threading::GetCurrentThread;

use crate::detail::*;

pub use sunset_macro::*;

pub mod detail;
pub mod legacy;
pub mod utils;

#[macro_export]
macro_rules! install_hooks {
    (
        $(
            $hook_paths:path
        ),*
        $(,)?
    ) => {
        $(
            $crate::install_hook!(
                $hook_paths
            );
        )*
    };
}

pub unsafe fn write_jmp(src: *mut u8, dst: *mut u8) -> Option<()> {
    let relative_address = (dst as u32) - (src as u32) - 5;

    crate::utils::set_permission(src, 5, crate::utils::Perm::ExecuteReadWrite)?;
    *src = 0xE9;
    *(src.add(1) as *mut u32) = relative_address;
    Some(())
}

pub unsafe fn write_call(src: *mut u8, dst: *mut u8) -> Option<()> {
    let relative_address = (dst as u32) - (src as u32) - 5;

    crate::utils::set_permission(src, 5, crate::utils::Perm::ExecuteReadWrite)?;
    *src = 0xE8;
    *(src.add(1) as *mut u32) = relative_address;
    Some(())
}

pub unsafe fn write_push(src: *mut u8, dst: u32) -> Option<()> {
    crate::utils::set_permission(src, 5, crate::utils::Perm::ExecuteReadWrite)?;
    *src = 0x68;
    *(src.add(1) as *mut u32) = dst;
    Some(())
}

pub unsafe fn write_nop(addr: *mut u8, code_size: usize) -> Option<()> {
    crate::utils::set_permission(addr, code_size, crate::utils::Perm::ExecuteReadWrite)?;
    std::ptr::write_bytes(addr, 0x90, code_size);
    Some(())
}

#[repr(C, packed)]
pub union Register {
    pub pointer: *mut (),
    pub unsigned_integer: u32,
    pub signed_integer: i32,
    pub floating_point: f32,
}

#[repr(C, packed)]
pub struct InlineCtx {
    pub eflags: Register,
    pub edi: Register,
    pub esi: Register,
    pub ebp: Register,
    pub esp: Register,
    pub ebx: Register,
    pub edx: Register,
    pub ecx: Register,
    pub eax: Register,
}

type CallbackFuncPtr = extern "cdecl" fn(&mut InlineCtx);

#[derive(Debug)]
pub enum InlineHookErr {
    // The size of the code at the desired address cannot be made large enough to fit a 5-byte JMP.
    InvalidCodeSize,

    // Failed to relocate code from the source to a trampoline.
    FailedToRelocateCode,
}

static mut JIT_MEMORY: Lazy<Mutex<Vec<JitMemory>>> = Lazy::new(|| Mutex::new(vec![]));

pub unsafe fn inline_hook(ptr: usize, callback: CallbackFuncPtr) -> Result<(), InlineHookErr> {
    // Calculate the minimum bytes needed to be backed up, and an upper-bound limit of how many bytes the relocated code could take. (Used for below allocation)
    let (original_code_len, padded_code_len) = find_suitable_backup_size(ptr as *const u8);

    if original_code_len < 5 {
        Err(InlineHookErr::InvalidCodeSize)
    } else {
        let jit_area = JitMemory::new(11 + padded_code_len + 5);
        // Build inline handler.
        jit_area.data[0] = 0x60; // pushad
        jit_area.data[1] = 0x9C; // pushfd
        jit_area.data[2] = 0x54; // push esp
        write_call(jit_area.data.as_mut_ptr().offset(3), callback as *mut u8).unwrap(); // call callback
        jit_area.data[8] = 0x58; // pop eax (We don't actually need to use EAX later, its just that a ``pop eax`` takes fewer bytes than a ``add esp, 4``.)
        jit_area.data[9] = 0x9D; // popfd
        jit_area.data[10] = 0x61; // popad

        // Attempt to build/relocate the code, and if successful, copy into the trampoline.
        match relocate_code(
            ptr as usize,
            original_code_len,
            jit_area.data.as_ptr().offset(11) as usize,
        ) {
            Ok(relocated) => {
                jit_area.data[11..11 + relocated.len()].copy_from_slice(&relocated);

                let old_perm = crate::utils::set_permission(
                    ptr as *mut u8,
                    original_code_len,
                    crate::utils::Perm::ExecuteReadWrite,
                )
                .unwrap();

                // Insert jmp from the inline handler back to the original function.
                write_jmp(
                    jit_area.data.as_mut_ptr().offset((11 + relocated.len()) as isize),
                    (ptr + 5) as *mut u8,
                )
                .unwrap();

                // Ensure original function has the trampoline area nop'd out.
                write_nop(ptr as *mut u8, original_code_len);

                // Insert jmp from the source to the inline handler.
                write_jmp(ptr as *mut u8, jit_area.data.as_mut_ptr());

                // Reset the permission at the source.
                crate::utils::set_permission(ptr as *mut u8, original_code_len, old_perm).unwrap();

                let mut vec = JIT_MEMORY.lock().unwrap();
                vec.push(jit_area);

                Ok(())
            }
            Err(err) => {
                dbg!(err);
                Err(InlineHookErr::FailedToRelocateCode)
            }
        }
    }
}

pub unsafe fn replace_hook<F>(ptr: &mut F, callback: *const ()) {
    detours_sys::DetourTransactionBegin();
    detours_sys::DetourUpdateThread(GetCurrentThread() as _);
    detours_sys::DetourAttach(std::mem::transmute(ptr), std::mem::transmute(callback));
    detours_sys::DetourTransactionCommit();
}

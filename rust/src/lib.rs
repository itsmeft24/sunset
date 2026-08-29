use std::{ptr::with_exposed_provenance, sync::Mutex};

use once_cell::sync::Lazy;
use utils::JitMemory;
use windows_sys::Win32::System::Threading::GetCurrentThread;

pub use sunset_macro::*;

use crate::detail::relocate_code;
#[cfg(target_arch = "x86_64")]
use crate::detail::x64 as arch;
#[cfg(target_arch = "x86")]
use crate::detail::x86 as arch;

pub mod detail;
pub mod inst;
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

#[cfg(target_arch = "x86_64")]
#[repr(C, packed)]
pub union Register {
    pub pointer: *mut (),
    pub unsigned_integer: u64,
    pub signed_integer: i64,
    pub floating_point: f64,
}

#[cfg(target_arch = "x86")]
#[repr(C, packed)]
pub union Register {
    pub pointer: *mut (),
    pub unsigned_integer: u32,
    pub signed_integer: i32,
    pub floating_point: f32,
}

#[repr(C, packed)]
pub union XMMRegister {
    f32: [f32; 4],
    f64: [f64; 2],
    i8: [i8; 16],
    u8: [i8; 16],
    i16: [i16; 8],
    u16: [i16; 8],
    i32: [i32; 4],
    u32: [i32; 4],
    i64: [i64; 2],
    u64: [u64; 2],
}

#[cfg(target_arch = "x86_64")]
#[repr(C, packed)]
pub struct InlineCtx {
    pub rflags: Register,
    pub r15: Register,
    pub r14: Register,
    pub r13: Register,
    pub r12: Register,
    pub r11: Register,
    pub r10: Register,
    pub r9: Register,
    pub r8: Register,
    pub rdi: Register,
    pub rsi: Register,
    pub rsp: Register,
    pub rbp: Register,
    pub rbx: Register,
    pub rdx: Register,
    pub rcx: Register,
    pub rax: Register,
}

#[cfg(target_arch = "x86")]
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

#[cfg(target_arch = "x86_64")]
#[repr(C, packed)]
pub struct InlineCtxEx {
    pub xmm15: XMMRegister,
    pub xmm14: XMMRegister,
    pub xmm13: XMMRegister,
    pub xmm12: XMMRegister,
    pub xmm11: XMMRegister,
    pub xmm10: XMMRegister,
    pub xmm9: XMMRegister,
    pub xmm8: XMMRegister,
    pub xmm7: XMMRegister,
    pub xmm6: XMMRegister,
    pub xmm5: XMMRegister,
    pub xmm4: XMMRegister,
    pub xmm3: XMMRegister,
    pub xmm2: XMMRegister,
    pub xmm1: XMMRegister,
    pub xmm0: XMMRegister,
    pub rflags: Register,
    pub r15: Register,
    pub r14: Register,
    pub r13: Register,
    pub r12: Register,
    pub r11: Register,
    pub r10: Register,
    pub r9: Register,
    pub r8: Register,
    pub rdi: Register,
    pub rsi: Register,
    pub rsp: Register,
    pub rbp: Register,
    pub rbx: Register,
    pub rdx: Register,
    pub rcx: Register,
    pub rax: Register,
}

#[cfg(target_arch = "x86")]
#[repr(C, packed)]
pub struct InlineCtxEx {
    pub xmm7: XMMRegister,
    pub xmm6: XMMRegister,
    pub xmm5: XMMRegister,
    pub xmm4: XMMRegister,
    pub xmm3: XMMRegister,
    pub xmm2: XMMRegister,
    pub xmm1: XMMRegister,
    pub xmm0: XMMRegister,
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
type ExCallbackFuncPtr = extern "cdecl" fn(&mut InlineCtxEx);

#[derive(Debug)]
pub enum InlineHookErr {
    // The user-set address does not have enough free space (>= 5 Bytes) for a jmp instruction.
    NotEnoughSpaceToInsertJump,
    // The callback function is too far away from the inline handler to use a 6-Byte call-indirect instruction.
    CallbackTooFarFromInlineHandler,
    // The original function is too far away from the inline handler to use 5-Byte jmp instructions.
    OriginalCodeTooFarFromInlineHandler,
}

static mut JIT_MEMORY: Lazy<Mutex<Vec<JitMemory>>> = Lazy::new(|| Mutex::new(vec![]));

const ADDRESS_SIZE: usize = std::mem::size_of::<usize>();

pub unsafe fn inline_hook(ptr: usize, callback: CallbackFuncPtr) -> Result<(), InlineHookErr> {
    // Calculate the minimum bytes needed to be backed up, and an upper-bound limit of how many bytes the relocated code could take. (Used for below allocation)
    let (original_code_len, padded_code_len) = detail::find_suitable_backup_size(ptr as *const u8);

    if original_code_len < detail::MINIMUM_OVERWRITE {
        return Err(InlineHookErr::NotEnoughSpaceToInsertJump);
    }

    // Allocate code for inline handler.
    // The size of the JIT memory block should be able to account for:
    //  - A pointer to Derived::callback (sizeof(void*))
    //  - The register backup routine
    //  - A 6-byte indirect call instruction to call Derived::callback (6)
    //  - The register restore routine
    //  - A 5-byte jump instruction to return to the original code (5)
    let jit_area_len = arch::BACKUP_GENERAL_REGISTERS.len()
        + arch::RESTORE_GENERAL_REGISTERS.len()
        + 6
        + padded_code_len
        + 5
        + ADDRESS_SIZE;

    #[cfg(target_arch = "x86_64")]
    // On x64, if we can't find any free space nearby, we have to panic.
    let jit_area = utils::allocate_near(ptr, jit_area_len, i32::MAX as usize).unwrap();
    #[cfg(target_arch = "x86")]
    // But on x86, we can reliably fall back to a plain ol' VirtualAlloc.
    let jit_area = utils::allocate_near(ptr, jit_area_len, i32::MAX as usize)
        .unwrap_or(utils::JitMemory::new(jit_area_len));

    // Write the callback address at the start of the inline handler, so we can use a call-indirect instruction to get there.
    jit_area.data[0..ADDRESS_SIZE].copy_from_slice(&usize::to_ne_bytes(
        (callback as *const ()).expose_provenance(),
    ));

    // Build inline handler.
    jit_area.data[ADDRESS_SIZE..ADDRESS_SIZE + arch::BACKUP_GENERAL_REGISTERS.len()]
        .copy_from_slice(&arch::BACKUP_GENERAL_REGISTERS);
    // The address of the callback is held at the start of the JIT memory, so we'll use jit_area.data.as_ptr() here.
    if !inst::call_indirect(
        jit_area
            .data
            .as_mut_ptr()
            .add(ADDRESS_SIZE + arch::BACKUP_GENERAL_REGISTERS.len()) as *mut (),
        jit_area.data.as_mut_ptr() as *mut (),
    ) {
        // This should be infallible since it will literally only be a few hundred bytes away tops...
        return Err(InlineHookErr::CallbackTooFarFromInlineHandler);
    }
    jit_area.data[ADDRESS_SIZE + arch::BACKUP_GENERAL_REGISTERS.len() + 6
        ..ADDRESS_SIZE
            + arch::BACKUP_GENERAL_REGISTERS.len()
            + 6
            + arch::RESTORE_GENERAL_REGISTERS.len()]
        .copy_from_slice(&arch::RESTORE_GENERAL_REGISTERS);

    // Attempt to build/relocate the code, and if successful, copy into the trampoline.
    let relocated = relocate_code(
        ptr,
        original_code_len,
        jit_area
            .data
            .as_ptr()
            .add(
                ADDRESS_SIZE
                    + arch::BACKUP_GENERAL_REGISTERS.len()
                    + 6
                    + arch::RESTORE_GENERAL_REGISTERS.len(),
            )
            .expose_provenance(),
    )
    .unwrap();
    jit_area.data[ADDRESS_SIZE
        + arch::BACKUP_GENERAL_REGISTERS.len()
        + 6
        + arch::RESTORE_GENERAL_REGISTERS.len()
        ..ADDRESS_SIZE
            + arch::BACKUP_GENERAL_REGISTERS.len()
            + 6
            + arch::RESTORE_GENERAL_REGISTERS.len()
            + relocated.len()]
        .copy_from_slice(&relocated);

    // Write the jmp from the inline handler back to the original function.
    if !inst::jmp(
        jit_area.data.as_mut_ptr().add(
            ADDRESS_SIZE
                + arch::BACKUP_GENERAL_REGISTERS.len()
                + 6
                + arch::RESTORE_GENERAL_REGISTERS.len()
                + relocated.len(),
        ) as *mut (),
        with_exposed_provenance::<()>(ptr + original_code_len) as *mut (),
    ) {
        return Err(InlineHookErr::OriginalCodeTooFarFromInlineHandler);
    }

    // Ensure original function has the trampoline area nop'd out before inserting the jmp from the source to the inline handler (jmp ptr).
    inst::nop(
        with_exposed_provenance::<()>(ptr) as *mut (),
        original_code_len,
    );
    if !inst::jmp(
        with_exposed_provenance::<()>(ptr) as *mut (),
        jit_area.data.as_mut_ptr().add(ADDRESS_SIZE) as *mut (),
    ) {
        return Err(InlineHookErr::OriginalCodeTooFarFromInlineHandler);
    }

    let mut vec = JIT_MEMORY.lock().unwrap();
    vec.push(jit_area);

    Ok(())
}

pub unsafe fn extended_inline_hook(
    ptr: usize,
    callback: ExCallbackFuncPtr,
) -> Result<(), InlineHookErr> {
    // Calculate the minimum bytes needed to be backed up, and an upper-bound limit of how many bytes the relocated code could take. (Used for below allocation)
    let (original_code_len, padded_code_len) = detail::find_suitable_backup_size(ptr as *const u8);

    if original_code_len < detail::MINIMUM_OVERWRITE {
        return Err(InlineHookErr::NotEnoughSpaceToInsertJump);
    }

    // Allocate code for inline handler.
    // The size of the JIT memory block should be able to account for:
    //  - A pointer to Derived::callback (sizeof(void*))
    //  - The register backup routine
    //  - A 6-byte indirect call instruction to call Derived::callback (6)
    //  - The register restore routine
    //  - A 5-byte jump instruction to return to the original code (5)
    let jit_area_len = arch::BACKUP_REGISTERS.len()
        + arch::RESTORE_REGISTERS.len()
        + 6
        + padded_code_len
        + 5
        + std::mem::size_of::<*const ()>();

    #[cfg(target_arch = "x86_64")]
    // On x64, if we can't find any free space nearby, we have to panic.
    let jit_area = utils::allocate_near(ptr, jit_area_len, i32::MAX as usize).unwrap();
    #[cfg(target_arch = "x86")]
    // But on x86, we can reliably fall back to a plain ol' VirtualAlloc.
    let jit_area = utils::allocate_near(ptr, jit_area_len, i32::MAX as usize)
        .unwrap_or(utils::JitMemory::new(jit_area_len));

    // Write the callback address at the start of the inline handler, so we can use a call-indirect instruction to get there.
    jit_area.data[0..ADDRESS_SIZE].copy_from_slice(&usize::to_ne_bytes(
        (callback as *const ()).expose_provenance(),
    ));

    // Build inline handler.
    jit_area.data[ADDRESS_SIZE..ADDRESS_SIZE + arch::BACKUP_REGISTERS.len()]
        .copy_from_slice(&arch::BACKUP_REGISTERS);
    // The address of the callback is held at the start of the JIT memory, so we'll use jit_area.data.as_ptr() here.
    if !inst::call_indirect(
        jit_area
            .data
            .as_mut_ptr()
            .add(ADDRESS_SIZE + arch::BACKUP_REGISTERS.len()) as *mut (),
        jit_area.data.as_mut_ptr() as *mut (),
    ) {
        // This should be infallible since it will literally only be a few hundred bytes away tops...
        return Err(InlineHookErr::CallbackTooFarFromInlineHandler);
    }
    jit_area.data[ADDRESS_SIZE + arch::BACKUP_REGISTERS.len() + 6
        ..ADDRESS_SIZE + arch::BACKUP_REGISTERS.len() + 6 + arch::RESTORE_REGISTERS.len()]
        .copy_from_slice(&arch::RESTORE_REGISTERS);

    // Attempt to build/relocate the code, and if successful, copy into the trampoline.
    let relocated = relocate_code(
        ptr,
        original_code_len,
        jit_area
            .data
            .as_ptr()
            .add(ADDRESS_SIZE + arch::BACKUP_REGISTERS.len() + 6 + arch::RESTORE_REGISTERS.len())
            .expose_provenance(),
    )
    .unwrap();
    jit_area.data[ADDRESS_SIZE + arch::BACKUP_REGISTERS.len() + 6 + arch::RESTORE_REGISTERS.len()
        ..ADDRESS_SIZE
            + arch::BACKUP_REGISTERS.len()
            + 6
            + arch::RESTORE_REGISTERS.len()
            + relocated.len()]
        .copy_from_slice(&relocated);

    // Write the jmp from the inline handler back to the original function.
    if !inst::jmp(
        jit_area.data.as_mut_ptr().add(
            ADDRESS_SIZE
                + arch::BACKUP_REGISTERS.len()
                + 6
                + arch::RESTORE_REGISTERS.len()
                + relocated.len(),
        ) as *mut (),
        with_exposed_provenance::<()>(ptr + original_code_len) as *mut (),
    ) {
        return Err(InlineHookErr::OriginalCodeTooFarFromInlineHandler);
    }

    // Ensure original function has the trampoline area nop'd out before inserting the jmp from the source to the inline handler (jmp ptr).
    inst::nop(
        with_exposed_provenance::<()>(ptr) as *mut (),
        original_code_len,
    );
    if !inst::jmp(
        with_exposed_provenance::<()>(ptr) as *mut (),
        jit_area.data.as_mut_ptr().add(ADDRESS_SIZE) as *mut (),
    ) {
        return Err(InlineHookErr::OriginalCodeTooFarFromInlineHandler);
    }

    let mut vec = JIT_MEMORY.lock().unwrap();
    vec.push(jit_area);

    Ok(())
}

pub unsafe fn replace_hook<F>(ptr: &mut F, callback: *const ()) {
    detours_sys::DetourTransactionBegin();
    detours_sys::DetourUpdateThread(GetCurrentThread() as _);
    detours_sys::DetourAttach(std::mem::transmute(ptr), std::mem::transmute(callback));
    detours_sys::DetourTransactionCommit();
}

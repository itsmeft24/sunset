use crate::utils;
use std::slice;

pub unsafe fn jmp(src: *mut (), dst: *mut ()) -> bool {
    let destination_address = dst.expose_provenance();
    let source_address = src.expose_provenance();
    let relative_address = (destination_address - source_address - 5) as isize;

    if relative_address < i32::MIN as isize || relative_address > i32::MAX as isize {
        return false;
    }

    let restore = utils::set_permission(src, 5, utils::Access::ExecuteReadWrite).unwrap();

    let target = source_address as *mut u8;
    utils::write_data(target, &[0xE9]);
    utils::write_data(target.add(1), &(relative_address as i32).to_ne_bytes());

    utils::set_permission(source_address as *mut (), 5, restore);
    true
}

pub unsafe fn call(src: *mut (), dst: *mut ()) -> bool {
    let destination_address = dst.expose_provenance();
    let source_address = src.expose_provenance();
    let relative_address = (destination_address - source_address - 5) as isize;

    if relative_address < i32::MIN as isize || relative_address > i32::MAX as isize {
        return false;
    }

    let restore = utils::set_permission(src, 5, utils::Access::ExecuteReadWrite).unwrap();

    let target = source_address as *mut u8;
    utils::write_data(target, &[0xE8]);
    utils::write_data(target.add(1), &(relative_address as i32).to_ne_bytes());

    utils::set_permission(source_address as *mut (), 5, restore);
    true
}

#[cfg(target_arch = "x86_64")]
pub unsafe fn call_indirect(src: *mut (), dst: *mut ()) -> bool {
    let destination_address = dst.expose_provenance();
    let source_address = src.expose_provenance();
    let relative_address = (destination_address - source_address - 6) as isize;

    if relative_address < i32::MIN as isize || relative_address > i32::MAX as isize {
        return false;
    }

    let restore = utils::set_permission(src, 6, utils::Access::ExecuteReadWrite).unwrap();

    let target = source_address as *mut u8;
    utils::write_data(target, &[0xFF, 0x15]);
    utils::write_data(target.add(2), &(relative_address as i32).to_ne_bytes());

    utils::set_permission(source_address as *mut (), 6, restore);
    true
}

#[cfg(target_arch = "x86")]
pub unsafe fn call_indirect(src: *mut (), dst: *mut ()) -> bool {
    let destination_address = dst as u32;
    let source_address = src.expose_provenance();

    let restore = utils::set_permission(src, 6, utils::Access::ExecuteReadWrite).unwrap();

    let target = source_address as *mut u8;
    utils::write_data(target, &[0xFF, 0x15]);
    utils::write_data(target.add(2), &destination_address.to_ne_bytes());

    utils::set_permission(source_address as *mut (), 6, restore);
    true
}

pub unsafe fn push_u32(src: *mut (), val: u32) {
    let source_address = src.expose_provenance();
    let restore = utils::set_permission(src, 5, utils::Access::ExecuteReadWrite).unwrap();

    let target = source_address as *mut u8;
    utils::write_data(target, &[0x68]);
    utils::write_data(target.add(1), &val.to_ne_bytes());

    utils::set_permission(source_address as *mut (), 5, restore);
}

pub unsafe fn push_u8(src: *mut (), val: u8) {
    let source_address = src.expose_provenance();
    let restore = utils::set_permission(src, 2, utils::Access::ExecuteReadWrite).unwrap();

    let target = source_address as *mut u8;
    utils::write_data(target, &[0x68]);
    utils::write_data(target.add(1), &[val]);

    utils::set_permission(source_address as *mut (), 2, restore);
}

pub unsafe fn nop(addr: *mut (), code_size: usize) {
    let restore = utils::set_permission(addr, code_size, utils::Access::ExecuteReadWrite).unwrap();
    slice::from_raw_parts_mut(addr as *mut u8, code_size).fill(0x90);
    utils::set_permission(addr, code_size, restore).unwrap();
}

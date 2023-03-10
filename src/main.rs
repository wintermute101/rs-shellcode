use std::arch::asm;
use std::process::Termination;

// #![windows_subsystem = "windows"]
use bindings::windows::win32::system_services::VirtualAlloc;
use clap::{App, Arg};
pub const PAGE_EXECUTE_READWRITE: u32 = 0x40;
pub const MEM_COMMIT: u32 = 0x1000;
pub const MEM_RESERVE: u32 = 0x2000;

struct ShellExit{
    err: Result<(), String>,
}

impl ShellExit{
    fn err(err: &str) -> Self{
        ShellExit { err: Err(err.to_owned()) }
    }
    fn ok() -> Self{
        ShellExit { err: Ok(()) }
    }
}

impl Termination for ShellExit{
    fn report(self) -> std::process::ExitCode {
        match self.err{
            Ok(()) => std::process::ExitCode::from(0),
            Err(e) => { eprintln!("[-] {e}"); std::process::ExitCode::from(1)}
        }
    }
}

fn main() -> ShellExit {
    let matches = App::new("rs_shellcode")
        .arg(
            Arg::new("file")
                .short('f')
                .about("shellcode path")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::new("breakpoint")
                .short('b')
                .about("set breakpoint in debugger"),
        )
        .arg(
            Arg::new("offset")
                .short('o')
                .about("shellcode offset")
                .takes_value(true),
        )
        .arg(
            Arg::new("xor")
                .short('x')
                .about("deobfuscate with XOR encoding")
                .takes_value(true),
        )
        .get_matches();

    let set_breakpoint = matches.is_present("breakpoint");
    if set_breakpoint {
        println!("[*] Breakpoint flag set!");
    }
    let fp: String = matches.value_of_t("file").unwrap_or_else(|e| e.exit());
    let offset: u64 = match matches.value_of("offset") {
        Some(offset) => {
            if offset.find("0x") == Some(0) {
                let without_prefix = offset.trim_start_matches("0x");
                u64::from_str_radix(without_prefix, 16).unwrap_or(0)
            } else {
                u64::from_str_radix(offset, 10).unwrap_or(0)
            }
        }
        _ => 0,
    };
    let xor = match matches.value_of("xor"){
        Some(x) => {
            if x.find("0x") == Some(0) {
                let without_prefix = x.trim_start_matches("0x");
                match u8::from_str_radix(without_prefix, 16).map_err(|e| ShellExit::err(&format!("xor should be one byte - {}", e))){
                    Ok(x) => Some(x),
                    Err(e) => return e,
                }
            }
            else{
                return ShellExit::err("xor shoud be in format 0xff");
            }
        },
        _ => None,
    };
    println!("[*] Reading shellcode from path: {:?}", fp.clone());
    let mut contents = match std::fs::read(fp) {
        Ok(res) => res,
        Err(e) => {
            return ShellExit::err(&format!("Reading shellcode error: {}", e));
        }
    };
    let flen = contents.len();

    if let Some(xor) = xor{
        println!("[*] Using xor 0x{xor:02x} to deobfuscate shellcode");
        contents.iter_mut().for_each(|x| *x = *x ^ xor);
    }

    if flen as u64 <= offset {
        return ShellExit::err(&format!(
            "Offset too big, offset: {}, file length: {}",
            offset, flen
        ));
    }
    let new_buf = unsafe {
        VirtualAlloc(
            std::ptr::null_mut(),
            flen,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        )
    };
    if new_buf == std::ptr::null_mut() {
        return ShellExit::err("Failed to allocate memory");
    }
    let new_buf_ptr: *mut u8 = new_buf as *mut u8 as _;
    unsafe { std::ptr::copy_nonoverlapping(contents.as_ptr(), new_buf_ptr, flen) };
    println!(
        "[*] Starting jmp to shellcode at offset 0x{:x} (base virtual address: {:p})",
        offset, new_buf_ptr
    );
    unsafe {
        let jmp_target = new_buf.offset(offset as isize);
        if set_breakpoint {
            asm!("int 3");
        }
        asm!("jmp {}",in(reg) jmp_target)
    };

    ShellExit::ok()
}

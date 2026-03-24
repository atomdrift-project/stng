//! Lightweight x86-64 emulator for garble string extraction.
//!
//! This emulator executes just enough x86-64 instructions to run garble's
//! Decrypt stub functions until they call `runtime.slicebytetostring`.
//!
//! # Design Goals
//!
//! - Minimal instruction set: only what garble code generation uses
//! - Simple memory model: mapped regions for .text, .rodata, stack
//! - Stop on slicebytetostring call to capture decrypted bytes
//!
//! # Supported Instructions
//!
//! Data Movement: MOV, LEA, MOVZX, MOVSX, PUSH, POP
//! Arithmetic: ADD, SUB, XOR, AND, OR, INC, DEC, NEG, NOT, IMUL
//! Compare/Test: CMP, TEST
//! Control Flow: JMP, Jcc, CALL, RET
//! SSE: MOVUPS, MOVAPS, MOVDQU, MOVDQA, PXOR
//! Misc: NOP, INT3

use iced_x86::{Decoder, DecoderOptions, Instruction, MemorySize, Mnemonic, OpKind, Register};
use std::collections::HashMap;

/// Get byte size from iced-x86 MemorySize.
fn memory_size_bytes(size: MemorySize) -> usize {
    match size {
        MemorySize::UInt8 | MemorySize::Int8 => 1,
        MemorySize::UInt16 | MemorySize::Int16 => 2,
        MemorySize::UInt32 | MemorySize::Int32 | MemorySize::Float32 => 4,
        MemorySize::UInt128
        | MemorySize::Int128
        | MemorySize::Float128
        | MemorySize::Packed128_Float32
        | MemorySize::Packed128_Float64
        | MemorySize::Packed128_UInt8
        | MemorySize::Packed128_Int8
        | MemorySize::Packed128_UInt16
        | MemorySize::Packed128_Int16
        | MemorySize::Packed128_UInt32
        | MemorySize::Packed128_Int32
        | MemorySize::Packed128_UInt64
        | MemorySize::Packed128_Int64 => 16,
        // UInt64, Int64, Float64, and any unknown sizes default to 8 bytes
        _ => 8,
    }
}

/// Get byte size from iced-x86 Register.
fn register_size_bytes(reg: Register) -> usize {
    match reg {
        // 8-bit registers
        Register::AL
        | Register::CL
        | Register::DL
        | Register::BL
        | Register::AH
        | Register::CH
        | Register::DH
        | Register::BH
        | Register::SPL
        | Register::BPL
        | Register::SIL
        | Register::DIL
        | Register::R8L
        | Register::R9L
        | Register::R10L
        | Register::R11L
        | Register::R12L
        | Register::R13L
        | Register::R14L
        | Register::R15L => 1,
        // 16-bit registers
        Register::AX
        | Register::CX
        | Register::DX
        | Register::BX
        | Register::SP
        | Register::BP
        | Register::SI
        | Register::DI
        | Register::R8W
        | Register::R9W
        | Register::R10W
        | Register::R11W
        | Register::R12W
        | Register::R13W
        | Register::R14W
        | Register::R15W => 2,
        // 32-bit registers
        Register::EAX
        | Register::ECX
        | Register::EDX
        | Register::EBX
        | Register::ESP
        | Register::EBP
        | Register::ESI
        | Register::EDI
        | Register::R8D
        | Register::R9D
        | Register::R10D
        | Register::R11D
        | Register::R12D
        | Register::R13D
        | Register::R14D
        | Register::R15D => 4,
        // XMM registers (128-bit)
        Register::XMM0
        | Register::XMM1
        | Register::XMM2
        | Register::XMM3
        | Register::XMM4
        | Register::XMM5
        | Register::XMM6
        | Register::XMM7
        | Register::XMM8
        | Register::XMM9
        | Register::XMM10
        | Register::XMM11
        | Register::XMM12
        | Register::XMM13
        | Register::XMM14
        | Register::XMM15 => 16,
        // 64-bit registers and default
        _ => 8,
    }
}

/// Emulation result.
#[derive(Debug)]
pub enum EmulationResult {
    /// Hit target function (e.g., slicebytetostring)
    HitTarget {
        /// Decrypted string bytes
        bytes: Vec<u8>,
        /// Length of the string
        len: usize,
    },
    /// Normal return from function
    Returned,
    /// Hit max instruction count
    MaxInstructions,
    /// Hit INT3 or invalid instruction
    Stopped,
    /// Error during emulation
    Error(String),
}

/// CPU state for x86-64 emulation.
#[derive(Debug, Clone, Default)]
pub struct CpuState {
    /// General purpose registers (RAX=0, RCX=1, RDX=2, RBX=3, RSP=4, RBP=5, RSI=6, RDI=7, R8-R15=8-15)
    pub regs: [u64; 16],
    /// Instruction pointer
    pub rip: u64,
    /// Flags register (simplified: just ZF, SF, CF, OF)
    pub rflags: u64,
    /// XMM registers (16 x 128-bit)
    pub xmm: [[u8; 16]; 16],
}

impl CpuState {
    /// Create new CPU state with stack pointer initialized.
    pub fn new(stack_top: u64) -> Self {
        let mut state = Self::default();
        state.regs[4] = stack_top; // RSP
        state.regs[5] = stack_top; // RBP
        state
    }

    // Flag bit positions
    const CF: u64 = 1 << 0; // Carry
    const ZF: u64 = 1 << 6; // Zero
    const SF: u64 = 1 << 7; // Sign
    const OF: u64 = 1 << 11; // Overflow

    /// Set zero flag based on value.
    #[inline]
    pub fn set_zf(&mut self, value: u64) {
        if value == 0 {
            self.rflags |= Self::ZF;
        } else {
            self.rflags &= !Self::ZF;
        }
    }

    /// Set sign flag based on value.
    #[inline]
    pub fn set_sf(&mut self, value: u64, bits: u32) {
        let sign_bit = 1u64 << (bits - 1);
        if value & sign_bit != 0 {
            self.rflags |= Self::SF;
        } else {
            self.rflags &= !Self::SF;
        }
    }

    /// Get zero flag.
    #[inline]
    pub fn zf(&self) -> bool {
        self.rflags & Self::ZF != 0
    }

    /// Get sign flag.
    #[inline]
    pub fn sf(&self) -> bool {
        self.rflags & Self::SF != 0
    }

    /// Get carry flag.
    #[inline]
    pub fn cf(&self) -> bool {
        self.rflags & Self::CF != 0
    }

    /// Get overflow flag.
    #[inline]
    pub fn of(&self) -> bool {
        self.rflags & Self::OF != 0
    }

    /// Set carry flag.
    #[inline]
    pub fn set_cf(&mut self, val: bool) {
        if val {
            self.rflags |= Self::CF;
        } else {
            self.rflags &= !Self::CF;
        }
    }

    /// Set overflow flag.
    #[inline]
    pub fn set_of(&mut self, val: bool) {
        if val {
            self.rflags |= Self::OF;
        } else {
            self.rflags &= !Self::OF;
        }
    }
}

/// Memory region for emulation.
#[derive(Debug, Clone)]
struct MemoryRegion {
    start: u64,
    data: Vec<u8>,
    writable: bool,
}

/// Memory model for emulation.
#[derive(Debug)]
pub struct Memory {
    regions: Vec<MemoryRegion>,
    /// Quick lookup cache for recent accesses
    last_region: Option<usize>,
}

impl Memory {
    /// Create empty memory.
    pub fn new() -> Self {
        Self {
            regions: Vec::new(),
            last_region: None,
        }
    }

    /// Map a memory region.
    pub fn map(&mut self, start: u64, data: Vec<u8>, writable: bool) {
        self.regions.push(MemoryRegion {
            start,
            data,
            writable,
        });
        self.regions.sort_by_key(|r| r.start);
        self.last_region = None;
    }

    /// Find region containing address.
    fn find_region(&mut self, addr: u64) -> Option<&mut MemoryRegion> {
        // Check cached region first
        if let Some(idx) = self.last_region {
            let region = &self.regions[idx];
            if addr >= region.start && addr < region.start + region.data.len() as u64 {
                return Some(&mut self.regions[idx]);
            }
        }

        // Linear search for region
        self.regions
            .iter_mut()
            .find(|region| addr >= region.start && addr < region.start + region.data.len() as u64)
    }

    /// Read bytes from memory.
    pub fn read(&mut self, addr: u64, size: usize) -> Option<Vec<u8>> {
        let region = self.find_region(addr)?;
        let offset = (addr - region.start) as usize;
        if offset + size > region.data.len() {
            return None;
        }
        Some(region.data[offset..offset + size].to_vec())
    }

    /// Read u64 from memory.
    pub fn read_u64(&mut self, addr: u64) -> Option<u64> {
        let bytes = self.read(addr, 8)?;
        Some(u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    /// Read u32 from memory.
    pub fn read_u32(&mut self, addr: u64) -> Option<u32> {
        let bytes = self.read(addr, 4)?;
        Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    /// Read u16 from memory.
    pub fn read_u16(&mut self, addr: u64) -> Option<u16> {
        let bytes = self.read(addr, 2)?;
        Some(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    /// Read u8 from memory.
    pub fn read_u8(&mut self, addr: u64) -> Option<u8> {
        let bytes = self.read(addr, 1)?;
        Some(bytes[0])
    }

    /// Write bytes to memory.
    pub fn write(&mut self, addr: u64, data: &[u8]) -> bool {
        let Some(region) = self.find_region(addr) else {
            return false;
        };
        if !region.writable {
            return false;
        }
        let offset = (addr - region.start) as usize;
        if offset + data.len() > region.data.len() {
            return false;
        }
        region.data[offset..offset + data.len()].copy_from_slice(data);
        true
    }

    /// Write u64 to memory.
    pub fn write_u64(&mut self, addr: u64, val: u64) -> bool {
        self.write(addr, &val.to_le_bytes())
    }

    /// Write u32 to memory.
    pub fn write_u32(&mut self, addr: u64, val: u32) -> bool {
        self.write(addr, &val.to_le_bytes())
    }

    /// Write u8 to memory.
    pub fn write_u8(&mut self, addr: u64, val: u8) -> bool {
        self.write(addr, &[val])
    }
}

impl Default for Memory {
    fn default() -> Self {
        Self::new()
    }
}

/// x86-64 emulator.
pub struct Emulator {
    /// CPU state
    pub cpu: CpuState,
    /// Memory
    pub mem: Memory,
    /// Target function addresses to stop at (e.g., slicebytetostring)
    pub targets: HashMap<u64, String>,
    /// Call stack for tracking returns
    call_stack: Vec<u64>,
    /// Maximum instructions to execute
    pub max_instructions: usize,
    /// Instructions executed
    pub instructions_executed: usize,
}

impl Emulator {
    /// Create new emulator.
    pub fn new() -> Self {
        Self {
            cpu: CpuState::default(),
            mem: Memory::new(),
            targets: HashMap::new(),
            call_stack: Vec::new(),
            max_instructions: 10000,
            instructions_executed: 0,
        }
    }

    /// Set up stack.
    pub fn setup_stack(&mut self, size: usize) {
        // Allocate stack at high address
        let stack_base = 0x7FFF_0000_0000u64;
        let stack_data = vec![0u8; size];
        self.mem.map(stack_base, stack_data, true);

        // Initialize RSP and RBP to top of stack
        let stack_top = stack_base + size as u64 - 8;
        self.cpu.regs[4] = stack_top; // RSP
        self.cpu.regs[5] = stack_top; // RBP
    }

    /// Load a section into memory.
    pub fn load_section(&mut self, addr: u64, data: &[u8], writable: bool) {
        self.mem.map(addr, data.to_vec(), writable);
    }

    /// Add a target function to stop at.
    pub fn add_target(&mut self, addr: u64, name: &str) {
        self.targets.insert(addr, name.to_string());
    }

    /// Set instruction pointer.
    pub fn set_rip(&mut self, addr: u64) {
        self.cpu.rip = addr;
    }

    /// Execute until target or limit reached.
    pub fn run(&mut self) -> EmulationResult {
        self.instructions_executed = 0;

        loop {
            if self.instructions_executed >= self.max_instructions {
                return EmulationResult::MaxInstructions;
            }

            // Fetch instruction bytes
            let Some(code) = self.mem.read(self.cpu.rip, 15) else {
                return EmulationResult::Error(format!("Cannot read code at {:#x}", self.cpu.rip));
            };

            // Decode instruction
            let mut decoder = Decoder::with_ip(64, &code, self.cpu.rip, DecoderOptions::NONE);
            let instr = decoder.decode();

            if instr.is_invalid() {
                return EmulationResult::Error(format!(
                    "Invalid instruction at {:#x}",
                    self.cpu.rip
                ));
            }

            // Execute
            match self.execute(&instr) {
                Ok(ExecResult::Continue) => {}
                Ok(ExecResult::HitTarget(bytes, len)) => {
                    return EmulationResult::HitTarget { bytes, len };
                }
                Ok(ExecResult::Return) => {
                    if self.call_stack.is_empty() {
                        return EmulationResult::Returned;
                    }
                }
                Ok(ExecResult::Stop) => {
                    return EmulationResult::Stopped;
                }
                Err(e) => {
                    return EmulationResult::Error(e);
                }
            }

            self.instructions_executed += 1;
        }
    }

    /// Execute single instruction.
    fn execute(&mut self, instr: &Instruction) -> Result<ExecResult, String> {
        let next_ip = self.cpu.rip + instr.len() as u64;

        match instr.mnemonic() {
            // NOP
            Mnemonic::Nop | Mnemonic::Fnop => {
                self.cpu.rip = next_ip;
            }

            // INT3 - stop
            Mnemonic::Int3 => {
                return Ok(ExecResult::Stop);
            }

            // MOV
            Mnemonic::Mov => {
                self.exec_mov(instr)?;
                self.cpu.rip = next_ip;
            }

            // LEA
            Mnemonic::Lea => {
                self.exec_lea(instr)?;
                self.cpu.rip = next_ip;
            }

            // MOVZX
            Mnemonic::Movzx => {
                self.exec_movzx(instr)?;
                self.cpu.rip = next_ip;
            }

            // MOVSX / MOVSXD
            Mnemonic::Movsx | Mnemonic::Movsxd => {
                self.exec_movsx(instr)?;
                self.cpu.rip = next_ip;
            }

            // PUSH
            Mnemonic::Push => {
                self.exec_push(instr)?;
                self.cpu.rip = next_ip;
            }

            // POP
            Mnemonic::Pop => {
                self.exec_pop(instr)?;
                self.cpu.rip = next_ip;
            }

            // ADD
            Mnemonic::Add => {
                self.exec_add(instr)?;
                self.cpu.rip = next_ip;
            }

            // SUB
            Mnemonic::Sub => {
                self.exec_sub(instr)?;
                self.cpu.rip = next_ip;
            }

            // XOR
            Mnemonic::Xor => {
                self.exec_xor(instr)?;
                self.cpu.rip = next_ip;
            }

            // AND
            Mnemonic::And => {
                self.exec_and(instr)?;
                self.cpu.rip = next_ip;
            }

            // OR
            Mnemonic::Or => {
                self.exec_or(instr)?;
                self.cpu.rip = next_ip;
            }

            // INC
            Mnemonic::Inc => {
                self.exec_inc(instr)?;
                self.cpu.rip = next_ip;
            }

            // DEC
            Mnemonic::Dec => {
                self.exec_dec(instr)?;
                self.cpu.rip = next_ip;
            }

            // NEG
            Mnemonic::Neg => {
                self.exec_neg(instr)?;
                self.cpu.rip = next_ip;
            }

            // NOT
            Mnemonic::Not => {
                self.exec_not(instr)?;
                self.cpu.rip = next_ip;
            }

            // CMP
            Mnemonic::Cmp => {
                self.exec_cmp(instr)?;
                self.cpu.rip = next_ip;
            }

            // TEST
            Mnemonic::Test => {
                self.exec_test(instr)?;
                self.cpu.rip = next_ip;
            }

            // JMP
            Mnemonic::Jmp => {
                self.cpu.rip = self.get_branch_target(instr)?;
            }

            // Conditional jumps
            Mnemonic::Je
            | Mnemonic::Jne
            | Mnemonic::Jl
            | Mnemonic::Jle
            | Mnemonic::Jg
            | Mnemonic::Jge
            | Mnemonic::Jb
            | Mnemonic::Jbe
            | Mnemonic::Ja
            | Mnemonic::Jae
            | Mnemonic::Js
            | Mnemonic::Jns => {
                if self.check_condition(instr.mnemonic()) {
                    self.cpu.rip = self.get_branch_target(instr)?;
                } else {
                    self.cpu.rip = next_ip;
                }
            }

            // CALL
            Mnemonic::Call => {
                let target = self.get_branch_target(instr)?;

                // Check if target is a function we want to intercept
                if let Some(name) = self.targets.get(&target) {
                    if name.contains("slicebytetostring") {
                        // Capture the string being converted
                        // Go calling convention: RAX=buf (unused), RBX=ptr, RCX=len (or on stack)
                        let ptr = self.cpu.regs[3]; // RBX
                        let len = self.cpu.regs[1]; // RCX
                        let bytes = self.mem.read(ptr, len as usize).unwrap_or_default();
                        return Ok(ExecResult::HitTarget(bytes, len as usize));
                    }
                }

                // Normal call - push return address
                self.cpu.regs[4] -= 8; // RSP
                self.mem.write_u64(self.cpu.regs[4], next_ip);
                self.call_stack.push(next_ip);
                self.cpu.rip = target;
            }

            // RET
            Mnemonic::Ret => {
                // Pop return address
                let Some(ret_addr) = self.mem.read_u64(self.cpu.regs[4]) else {
                    return Err("Cannot read return address".to_string());
                };
                self.cpu.regs[4] += 8; // RSP
                self.call_stack.pop();
                self.cpu.rip = ret_addr;

                if self.call_stack.is_empty() {
                    return Ok(ExecResult::Return);
                }
            }

            // SSE moves
            Mnemonic::Movups | Mnemonic::Movaps | Mnemonic::Movdqu | Mnemonic::Movdqa => {
                self.exec_sse_mov(instr)?;
                self.cpu.rip = next_ip;
            }

            // PXOR
            Mnemonic::Pxor => {
                self.exec_pxor(instr)?;
                self.cpu.rip = next_ip;
            }

            // Shifts
            Mnemonic::Shl | Mnemonic::Sal => {
                self.exec_shl(instr)?;
                self.cpu.rip = next_ip;
            }

            Mnemonic::Shr => {
                self.exec_shr(instr)?;
                self.cpu.rip = next_ip;
            }

            Mnemonic::Sar => {
                self.exec_sar(instr)?;
                self.cpu.rip = next_ip;
            }

            // IMUL
            Mnemonic::Imul => {
                self.exec_imul(instr)?;
                self.cpu.rip = next_ip;
            }

            // XCHG - handled specially for atomic ops but we can just swap
            Mnemonic::Xchg => {
                self.exec_xchg(instr)?;
                self.cpu.rip = next_ip;
            }

            // CMOV variants
            Mnemonic::Cmove
            | Mnemonic::Cmovne
            | Mnemonic::Cmovl
            | Mnemonic::Cmovle
            | Mnemonic::Cmovg
            | Mnemonic::Cmovge
            | Mnemonic::Cmovb
            | Mnemonic::Cmovbe
            | Mnemonic::Cmova
            | Mnemonic::Cmovae
            | Mnemonic::Cmovs
            | Mnemonic::Cmovns => {
                self.exec_cmov(instr)?;
                self.cpu.rip = next_ip;
            }

            // XORPS - zero XMM register
            Mnemonic::Xorps | Mnemonic::Xorpd => {
                self.exec_xorps(instr)?;
                self.cpu.rip = next_ip;
            }

            _ => {
                return Err(format!(
                    "Unsupported instruction: {:?} at {:#x}",
                    instr.mnemonic(),
                    self.cpu.rip
                ));
            }
        }

        Ok(ExecResult::Continue)
    }

    // Helper to get register value
    fn get_reg(&self, reg: Register) -> u64 {
        let (idx, mask) = Self::reg_info(reg);
        self.cpu.regs[idx] & mask
    }

    // Helper to set register value
    fn set_reg(&mut self, reg: Register, val: u64) {
        let (idx, mask) = Self::reg_info(reg);
        if mask == u64::MAX {
            self.cpu.regs[idx] = val;
        } else if mask == 0xFFFF_FFFF {
            // 32-bit write zero-extends to 64-bit
            self.cpu.regs[idx] = val & mask;
        } else {
            // 8/16-bit writes preserve upper bits
            self.cpu.regs[idx] = (self.cpu.regs[idx] & !mask) | (val & mask);
        }
    }

    // Map register to index and mask
    fn reg_info(reg: Register) -> (usize, u64) {
        match reg {
            Register::RAX | Register::EAX | Register::AX | Register::AL => {
                let mask = match reg {
                    Register::RAX => u64::MAX,
                    Register::EAX => 0xFFFF_FFFF,
                    Register::AX => 0xFFFF,
                    Register::AL => 0xFF,
                    _ => unreachable!(),
                };
                (0, mask)
            }
            Register::RCX | Register::ECX | Register::CX | Register::CL => {
                let mask = match reg {
                    Register::RCX => u64::MAX,
                    Register::ECX => 0xFFFF_FFFF,
                    Register::CX => 0xFFFF,
                    Register::CL => 0xFF,
                    _ => unreachable!(),
                };
                (1, mask)
            }
            Register::RDX | Register::EDX | Register::DX | Register::DL => {
                let mask = match reg {
                    Register::RDX => u64::MAX,
                    Register::EDX => 0xFFFF_FFFF,
                    Register::DX => 0xFFFF,
                    Register::DL => 0xFF,
                    _ => unreachable!(),
                };
                (2, mask)
            }
            Register::RBX | Register::EBX | Register::BX | Register::BL => {
                let mask = match reg {
                    Register::RBX => u64::MAX,
                    Register::EBX => 0xFFFF_FFFF,
                    Register::BX => 0xFFFF,
                    Register::BL => 0xFF,
                    _ => unreachable!(),
                };
                (3, mask)
            }
            Register::RSP | Register::ESP | Register::SP | Register::SPL => (4, u64::MAX),
            Register::RBP | Register::EBP | Register::BP | Register::BPL => (5, u64::MAX),
            Register::RSI | Register::ESI | Register::SI | Register::SIL => {
                let mask = match reg {
                    Register::RSI => u64::MAX,
                    Register::ESI => 0xFFFF_FFFF,
                    Register::SI => 0xFFFF,
                    Register::SIL => 0xFF,
                    _ => unreachable!(),
                };
                (6, mask)
            }
            Register::RDI | Register::EDI | Register::DI | Register::DIL => {
                let mask = match reg {
                    Register::RDI => u64::MAX,
                    Register::EDI => 0xFFFF_FFFF,
                    Register::DI => 0xFFFF,
                    Register::DIL => 0xFF,
                    _ => unreachable!(),
                };
                (7, mask)
            }
            Register::R8 | Register::R8D | Register::R8W | Register::R8L => {
                let mask = match reg {
                    Register::R8 => u64::MAX,
                    Register::R8D => 0xFFFF_FFFF,
                    Register::R8W => 0xFFFF,
                    Register::R8L => 0xFF,
                    _ => unreachable!(),
                };
                (8, mask)
            }
            Register::R9 | Register::R9D | Register::R9W | Register::R9L => {
                let mask = match reg {
                    Register::R9 => u64::MAX,
                    Register::R9D => 0xFFFF_FFFF,
                    Register::R9W => 0xFFFF,
                    Register::R9L => 0xFF,
                    _ => unreachable!(),
                };
                (9, mask)
            }
            Register::R10 | Register::R10D | Register::R10W | Register::R10L => {
                let mask = match reg {
                    Register::R10 => u64::MAX,
                    Register::R10D => 0xFFFF_FFFF,
                    Register::R10W => 0xFFFF,
                    Register::R10L => 0xFF,
                    _ => unreachable!(),
                };
                (10, mask)
            }
            Register::R11 | Register::R11D | Register::R11W | Register::R11L => {
                let mask = match reg {
                    Register::R11 => u64::MAX,
                    Register::R11D => 0xFFFF_FFFF,
                    Register::R11W => 0xFFFF,
                    Register::R11L => 0xFF,
                    _ => unreachable!(),
                };
                (11, mask)
            }
            Register::R12 | Register::R12D | Register::R12W | Register::R12L => {
                let mask = match reg {
                    Register::R12 => u64::MAX,
                    Register::R12D => 0xFFFF_FFFF,
                    Register::R12W => 0xFFFF,
                    Register::R12L => 0xFF,
                    _ => unreachable!(),
                };
                (12, mask)
            }
            Register::R13 | Register::R13D | Register::R13W | Register::R13L => {
                let mask = match reg {
                    Register::R13 => u64::MAX,
                    Register::R13D => 0xFFFF_FFFF,
                    Register::R13W => 0xFFFF,
                    Register::R13L => 0xFF,
                    _ => unreachable!(),
                };
                (13, mask)
            }
            Register::R14 | Register::R14D | Register::R14W | Register::R14L => {
                let mask = match reg {
                    Register::R14 => u64::MAX,
                    Register::R14D => 0xFFFF_FFFF,
                    Register::R14W => 0xFFFF,
                    Register::R14L => 0xFF,
                    _ => unreachable!(),
                };
                (14, mask)
            }
            Register::R15 | Register::R15D | Register::R15W | Register::R15L => {
                let mask = match reg {
                    Register::R15 => u64::MAX,
                    Register::R15D => 0xFFFF_FFFF,
                    Register::R15W => 0xFFFF,
                    Register::R15L => 0xFF,
                    _ => unreachable!(),
                };
                (15, mask)
            }
            Register::AH => (0, 0xFF00),
            Register::CH => (1, 0xFF00),
            Register::DH => (2, 0xFF00),
            Register::BH => (3, 0xFF00),
            _ => (0, 0), // Unknown register
        }
    }

    // Calculate memory address from instruction operand
    fn calc_mem_addr(&self, instr: &Instruction, _op: u32) -> u64 {
        let base = if instr.memory_base() != Register::None {
            self.get_reg(instr.memory_base())
        } else {
            0
        };

        let index = if instr.memory_index() != Register::None {
            self.get_reg(instr.memory_index()) * instr.memory_index_scale() as u64
        } else {
            0
        };

        let disp = instr.memory_displacement64();

        // Handle RIP-relative addressing
        if instr.memory_base() == Register::RIP {
            self.cpu.rip + instr.len() as u64 + disp
        } else {
            base.wrapping_add(index).wrapping_add(disp)
        }
    }

    // Get operand value
    fn get_operand(&mut self, instr: &Instruction, op: u32) -> Result<u64, String> {
        match instr.op_kind(op) {
            OpKind::Register => Ok(self.get_reg(instr.op_register(op))),
            OpKind::Immediate8
            | OpKind::Immediate8to16
            | OpKind::Immediate8to32
            | OpKind::Immediate8to64 => Ok(instr.immediate8() as u64),
            OpKind::Immediate16 => Ok(instr.immediate16() as u64),
            OpKind::Immediate32 | OpKind::Immediate32to64 => Ok(instr.immediate32() as u64),
            OpKind::Immediate64 => Ok(instr.immediate64()),
            OpKind::Memory => {
                let addr = self.calc_mem_addr(instr, op);
                let size = memory_size_bytes(instr.memory_size());
                match size {
                    1 => self.mem.read_u8(addr).map(|v| v as u64),
                    2 => self.mem.read_u16(addr).map(|v| v as u64),
                    4 => self.mem.read_u32(addr).map(|v| v as u64),
                    8 => self.mem.read_u64(addr),
                    _ => None,
                }
                .ok_or_else(|| format!("Cannot read memory at {:#x}", addr))
            }
            _ => Err(format!("Unsupported operand kind: {:?}", instr.op_kind(op))),
        }
    }

    // Set operand value
    fn set_operand(&mut self, instr: &Instruction, op: u32, val: u64) -> Result<(), String> {
        match instr.op_kind(op) {
            OpKind::Register => {
                self.set_reg(instr.op_register(op), val);
                Ok(())
            }
            OpKind::Memory => {
                let addr = self.calc_mem_addr(instr, op);
                let size = memory_size_bytes(instr.memory_size());
                let ok = match size {
                    1 => self.mem.write_u8(addr, val as u8),
                    2 => self.mem.write(addr, &(val as u16).to_le_bytes()),
                    4 => self.mem.write_u32(addr, val as u32),
                    8 => self.mem.write_u64(addr, val),
                    _ => false,
                };
                if ok {
                    Ok(())
                } else {
                    Err(format!("Cannot write memory at {:#x}", addr))
                }
            }
            _ => Err(format!("Cannot set operand kind: {:?}", instr.op_kind(op))),
        }
    }

    // Get branch target
    fn get_branch_target(&mut self, instr: &Instruction) -> Result<u64, String> {
        match instr.op0_kind() {
            OpKind::NearBranch64 => Ok(instr.near_branch64()),
            OpKind::NearBranch32 => Ok(instr.near_branch32() as u64),
            OpKind::NearBranch16 => Ok(instr.near_branch16() as u64),
            OpKind::Register => Ok(self.get_reg(instr.op0_register())),
            OpKind::Memory => {
                let addr = self.calc_mem_addr(instr, 0);
                self.mem
                    .read_u64(addr)
                    .ok_or_else(|| format!("Cannot read jump target at {:#x}", addr))
            }
            _ => Err(format!("Unsupported branch target: {:?}", instr.op0_kind())),
        }
    }

    // Check conditional jump condition
    fn check_condition(&self, mnemonic: Mnemonic) -> bool {
        match mnemonic {
            Mnemonic::Je => self.cpu.zf(),
            Mnemonic::Jne => !self.cpu.zf(),
            Mnemonic::Jl => self.cpu.sf() != self.cpu.of(),
            Mnemonic::Jle => self.cpu.zf() || (self.cpu.sf() != self.cpu.of()),
            Mnemonic::Jg => !self.cpu.zf() && (self.cpu.sf() == self.cpu.of()),
            Mnemonic::Jge => self.cpu.sf() == self.cpu.of(),
            Mnemonic::Jb => self.cpu.cf(),
            Mnemonic::Jbe => self.cpu.cf() || self.cpu.zf(),
            Mnemonic::Ja => !self.cpu.cf() && !self.cpu.zf(),
            Mnemonic::Jae => !self.cpu.cf(),
            Mnemonic::Js => self.cpu.sf(),
            Mnemonic::Jns => !self.cpu.sf(),
            _ => false,
        }
    }

    // Instruction implementations
    fn exec_mov(&mut self, instr: &Instruction) -> Result<(), String> {
        let val = self.get_operand(instr, 1)?;
        self.set_operand(instr, 0, val)
    }

    fn exec_lea(&mut self, instr: &Instruction) -> Result<(), String> {
        let addr = self.calc_mem_addr(instr, 1);
        self.set_operand(instr, 0, addr)
    }

    fn exec_movzx(&mut self, instr: &Instruction) -> Result<(), String> {
        let val = self.get_operand(instr, 1)?;
        self.set_operand(instr, 0, val)
    }

    fn exec_movsx(&mut self, instr: &Instruction) -> Result<(), String> {
        let val = self.get_operand(instr, 1)?;
        let src_bits = if instr.op1_kind() == OpKind::Register {
            register_size_bytes(instr.op1_register()) * 8
        } else {
            memory_size_bytes(instr.memory_size()) * 8
        };

        let sign_extended = match src_bits {
            8 => (val as i8) as i64 as u64,
            16 => (val as i16) as i64 as u64,
            32 => (val as i32) as i64 as u64,
            _ => val,
        };
        self.set_operand(instr, 0, sign_extended)
    }

    fn exec_push(&mut self, instr: &Instruction) -> Result<(), String> {
        let val = self.get_operand(instr, 0)?;
        self.cpu.regs[4] -= 8;
        self.mem.write_u64(self.cpu.regs[4], val);
        Ok(())
    }

    fn exec_pop(&mut self, instr: &Instruction) -> Result<(), String> {
        let val = self
            .mem
            .read_u64(self.cpu.regs[4])
            .ok_or("Stack underflow")?;
        self.cpu.regs[4] += 8;
        self.set_operand(instr, 0, val)
    }

    fn exec_add(&mut self, instr: &Instruction) -> Result<(), String> {
        let a = self.get_operand(instr, 0)?;
        let b = self.get_operand(instr, 1)?;
        let result = a.wrapping_add(b);
        self.set_operand(instr, 0, result)?;
        self.cpu.set_zf(result);
        self.cpu.set_sf(result, 64);
        Ok(())
    }

    fn exec_sub(&mut self, instr: &Instruction) -> Result<(), String> {
        let a = self.get_operand(instr, 0)?;
        let b = self.get_operand(instr, 1)?;
        let result = a.wrapping_sub(b);
        self.set_operand(instr, 0, result)?;
        self.cpu.set_zf(result);
        self.cpu.set_sf(result, 64);
        self.cpu.set_cf(a < b);
        Ok(())
    }

    fn exec_xor(&mut self, instr: &Instruction) -> Result<(), String> {
        let a = self.get_operand(instr, 0)?;
        let b = self.get_operand(instr, 1)?;
        let result = a ^ b;
        self.set_operand(instr, 0, result)?;
        self.cpu.set_zf(result);
        self.cpu.set_sf(result, 64);
        self.cpu.set_cf(false);
        self.cpu.set_of(false);
        Ok(())
    }

    fn exec_and(&mut self, instr: &Instruction) -> Result<(), String> {
        let a = self.get_operand(instr, 0)?;
        let b = self.get_operand(instr, 1)?;
        let result = a & b;
        self.set_operand(instr, 0, result)?;
        self.cpu.set_zf(result);
        self.cpu.set_sf(result, 64);
        self.cpu.set_cf(false);
        self.cpu.set_of(false);
        Ok(())
    }

    fn exec_or(&mut self, instr: &Instruction) -> Result<(), String> {
        let a = self.get_operand(instr, 0)?;
        let b = self.get_operand(instr, 1)?;
        let result = a | b;
        self.set_operand(instr, 0, result)?;
        self.cpu.set_zf(result);
        self.cpu.set_sf(result, 64);
        self.cpu.set_cf(false);
        self.cpu.set_of(false);
        Ok(())
    }

    fn exec_inc(&mut self, instr: &Instruction) -> Result<(), String> {
        let val = self.get_operand(instr, 0)?;
        let result = val.wrapping_add(1);
        self.set_operand(instr, 0, result)?;
        self.cpu.set_zf(result);
        self.cpu.set_sf(result, 64);
        Ok(())
    }

    fn exec_dec(&mut self, instr: &Instruction) -> Result<(), String> {
        let val = self.get_operand(instr, 0)?;
        let result = val.wrapping_sub(1);
        self.set_operand(instr, 0, result)?;
        self.cpu.set_zf(result);
        self.cpu.set_sf(result, 64);
        Ok(())
    }

    fn exec_neg(&mut self, instr: &Instruction) -> Result<(), String> {
        let val = self.get_operand(instr, 0)?;
        let result = (val as i64).wrapping_neg() as u64;
        self.set_operand(instr, 0, result)?;
        self.cpu.set_zf(result);
        self.cpu.set_sf(result, 64);
        self.cpu.set_cf(val != 0);
        Ok(())
    }

    fn exec_not(&mut self, instr: &Instruction) -> Result<(), String> {
        let val = self.get_operand(instr, 0)?;
        let result = !val;
        self.set_operand(instr, 0, result)
    }

    fn exec_cmp(&mut self, instr: &Instruction) -> Result<(), String> {
        let a = self.get_operand(instr, 0)?;
        let b = self.get_operand(instr, 1)?;
        let result = a.wrapping_sub(b);
        self.cpu.set_zf(result);
        self.cpu.set_sf(result, 64);
        self.cpu.set_cf(a < b);
        // Simplified overflow detection
        let a_sign = (a >> 63) & 1;
        let b_sign = (b >> 63) & 1;
        let r_sign = (result >> 63) & 1;
        self.cpu.set_of((a_sign != b_sign) && (a_sign != r_sign));
        Ok(())
    }

    fn exec_test(&mut self, instr: &Instruction) -> Result<(), String> {
        let a = self.get_operand(instr, 0)?;
        let b = self.get_operand(instr, 1)?;
        let result = a & b;
        self.cpu.set_zf(result);
        self.cpu.set_sf(result, 64);
        self.cpu.set_cf(false);
        self.cpu.set_of(false);
        Ok(())
    }

    fn exec_shl(&mut self, instr: &Instruction) -> Result<(), String> {
        let val = self.get_operand(instr, 0)?;
        let count = (self.get_operand(instr, 1)? & 0x3F) as u32;
        let result = val.wrapping_shl(count);
        self.set_operand(instr, 0, result)?;
        self.cpu.set_zf(result);
        self.cpu.set_sf(result, 64);
        Ok(())
    }

    fn exec_shr(&mut self, instr: &Instruction) -> Result<(), String> {
        let val = self.get_operand(instr, 0)?;
        let count = (self.get_operand(instr, 1)? & 0x3F) as u32;
        let result = val.wrapping_shr(count);
        self.set_operand(instr, 0, result)?;
        self.cpu.set_zf(result);
        self.cpu.set_sf(result, 64);
        Ok(())
    }

    fn exec_sar(&mut self, instr: &Instruction) -> Result<(), String> {
        let val = self.get_operand(instr, 0)? as i64;
        let count = (self.get_operand(instr, 1)? & 0x3F) as u32;
        let result = val.wrapping_shr(count) as u64;
        self.set_operand(instr, 0, result)?;
        self.cpu.set_zf(result);
        self.cpu.set_sf(result, 64);
        Ok(())
    }

    fn exec_imul(&mut self, instr: &Instruction) -> Result<(), String> {
        // Simplified IMUL - only handles common forms
        if instr.op_count() == 2 {
            let a = self.get_operand(instr, 0)? as i64;
            let b = self.get_operand(instr, 1)? as i64;
            let result = a.wrapping_mul(b) as u64;
            self.set_operand(instr, 0, result)?;
        } else if instr.op_count() == 3 {
            let b = self.get_operand(instr, 1)? as i64;
            let c = self.get_operand(instr, 2)? as i64;
            let result = b.wrapping_mul(c) as u64;
            self.set_operand(instr, 0, result)?;
        }
        Ok(())
    }

    fn exec_xchg(&mut self, instr: &Instruction) -> Result<(), String> {
        let a = self.get_operand(instr, 0)?;
        let b = self.get_operand(instr, 1)?;
        self.set_operand(instr, 0, b)?;
        self.set_operand(instr, 1, a)?;
        Ok(())
    }

    fn exec_cmov(&mut self, instr: &Instruction) -> Result<(), String> {
        let should_move = match instr.mnemonic() {
            Mnemonic::Cmove => self.cpu.zf(),
            Mnemonic::Cmovne => !self.cpu.zf(),
            Mnemonic::Cmovl => self.cpu.sf() != self.cpu.of(),
            Mnemonic::Cmovle => self.cpu.zf() || (self.cpu.sf() != self.cpu.of()),
            Mnemonic::Cmovg => !self.cpu.zf() && (self.cpu.sf() == self.cpu.of()),
            Mnemonic::Cmovge => self.cpu.sf() == self.cpu.of(),
            Mnemonic::Cmovb => self.cpu.cf(),
            Mnemonic::Cmovbe => self.cpu.cf() || self.cpu.zf(),
            Mnemonic::Cmova => !self.cpu.cf() && !self.cpu.zf(),
            Mnemonic::Cmovae => !self.cpu.cf(),
            Mnemonic::Cmovs => self.cpu.sf(),
            Mnemonic::Cmovns => !self.cpu.sf(),
            _ => false,
        };

        if should_move {
            let val = self.get_operand(instr, 1)?;
            self.set_operand(instr, 0, val)?;
        }
        Ok(())
    }

    fn exec_sse_mov(&mut self, instr: &Instruction) -> Result<(), String> {
        // Handle XMM register moves
        let is_store = instr.op0_kind() == OpKind::Memory;

        if is_store {
            // Store XMM to memory
            let reg = instr.op1_register();
            let xmm_idx = Self::xmm_index(reg)?;
            let addr = self.calc_mem_addr(instr, 0);
            self.mem.write(addr, &self.cpu.xmm[xmm_idx]);
        } else {
            // Load memory to XMM or XMM to XMM
            let dst_reg = instr.op0_register();
            let xmm_idx = Self::xmm_index(dst_reg)?;

            if instr.op1_kind() == OpKind::Register {
                let src_reg = instr.op1_register();
                let src_idx = Self::xmm_index(src_reg)?;
                self.cpu.xmm[xmm_idx] = self.cpu.xmm[src_idx];
            } else {
                let addr = self.calc_mem_addr(instr, 1);
                if let Some(data) = self.mem.read(addr, 16) {
                    self.cpu.xmm[xmm_idx].copy_from_slice(&data);
                }
            }
        }
        Ok(())
    }

    fn exec_pxor(&mut self, instr: &Instruction) -> Result<(), String> {
        let dst_reg = instr.op0_register();
        let dst_idx = Self::xmm_index(dst_reg)?;

        let src_data = if instr.op1_kind() == OpKind::Register {
            let src_reg = instr.op1_register();
            let src_idx = Self::xmm_index(src_reg)?;
            self.cpu.xmm[src_idx]
        } else {
            let addr = self.calc_mem_addr(instr, 1);
            let data = self.mem.read(addr, 16).ok_or("Cannot read XMM source")?;
            let mut arr = [0u8; 16];
            arr.copy_from_slice(&data);
            arr
        };

        for (dst, src) in self.cpu.xmm[dst_idx].iter_mut().zip(src_data.iter()) {
            *dst ^= src;
        }
        Ok(())
    }

    fn exec_xorps(&mut self, instr: &Instruction) -> Result<(), String> {
        let dst_reg = instr.op0_register();
        let dst_idx = Self::xmm_index(dst_reg)?;

        if instr.op1_kind() == OpKind::Register {
            let src_reg = instr.op1_register();
            let src_idx = Self::xmm_index(src_reg)?;

            // If same register, this zeros the register
            if dst_idx == src_idx {
                self.cpu.xmm[dst_idx] = [0; 16];
            } else {
                let src = self.cpu.xmm[src_idx];
                for (dst, src) in self.cpu.xmm[dst_idx].iter_mut().zip(src.iter()) {
                    *dst ^= src;
                }
            }
        } else {
            let addr = self.calc_mem_addr(instr, 1);
            if let Some(data) = self.mem.read(addr, 16) {
                for (dst, src) in self.cpu.xmm[dst_idx].iter_mut().zip(data.iter()) {
                    *dst ^= src;
                }
            }
        }
        Ok(())
    }

    fn xmm_index(reg: Register) -> Result<usize, String> {
        match reg {
            Register::XMM0 => Ok(0),
            Register::XMM1 => Ok(1),
            Register::XMM2 => Ok(2),
            Register::XMM3 => Ok(3),
            Register::XMM4 => Ok(4),
            Register::XMM5 => Ok(5),
            Register::XMM6 => Ok(6),
            Register::XMM7 => Ok(7),
            Register::XMM8 => Ok(8),
            Register::XMM9 => Ok(9),
            Register::XMM10 => Ok(10),
            Register::XMM11 => Ok(11),
            Register::XMM12 => Ok(12),
            Register::XMM13 => Ok(13),
            Register::XMM14 => Ok(14),
            Register::XMM15 => Ok(15),
            _ => Err(format!("Not an XMM register: {:?}", reg)),
        }
    }
}

impl Default for Emulator {
    fn default() -> Self {
        Self::new()
    }
}

/// Execution result for single instruction.
enum ExecResult {
    Continue,
    HitTarget(Vec<u8>, usize),
    Return,
    Stop,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_mov() {
        let mut emu = Emulator::new();
        emu.setup_stack(0x1000);

        // mov rax, 0x1234
        let code = [0x48, 0xc7, 0xc0, 0x34, 0x12, 0x00, 0x00];
        emu.load_section(0x1000, &code, false);
        emu.set_rip(0x1000);

        let mut decoder = Decoder::with_ip(64, &code, 0x1000, DecoderOptions::NONE);
        let instr = decoder.decode();

        emu.execute(&instr).unwrap();
        assert_eq!(emu.cpu.regs[0], 0x1234);
    }

    #[test]
    fn test_add_sub() {
        let mut emu = Emulator::new();
        emu.cpu.regs[0] = 10; // RAX = 10
        emu.cpu.regs[1] = 3; // RCX = 3

        // add rax, rcx
        let code = [0x48, 0x01, 0xc8];
        let mut decoder = Decoder::with_ip(64, &code, 0, DecoderOptions::NONE);
        let instr = decoder.decode();

        emu.execute(&instr).unwrap();
        assert_eq!(emu.cpu.regs[0], 13);
    }

    #[test]
    fn test_xor_zeroes() {
        let mut emu = Emulator::new();
        emu.cpu.regs[0] = 0xDEADBEEF;

        // xor eax, eax
        let code = [0x31, 0xc0];
        let mut decoder = Decoder::with_ip(64, &code, 0, DecoderOptions::NONE);
        let instr = decoder.decode();

        emu.execute(&instr).unwrap();
        assert_eq!(emu.cpu.regs[0], 0);
        assert!(emu.cpu.zf());
    }

    #[test]
    fn test_conditional_jump() {
        let mut emu = Emulator::new();
        emu.cpu.regs[0] = 5;
        emu.cpu.regs[1] = 5;

        // cmp rax, rcx
        let code = [0x48, 0x39, 0xc8];
        let mut decoder = Decoder::with_ip(64, &code, 0, DecoderOptions::NONE);
        let instr = decoder.decode();

        emu.execute(&instr).unwrap();
        assert!(emu.cpu.zf()); // Equal, so ZF=1
    }
}

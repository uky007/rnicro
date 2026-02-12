//! DWARF expression evaluator.
//!
//! Corresponds to book Ch.19 (DWARF Expressions).
//!
//! Wraps gimli's `Evaluation` to interpret DWARF location expressions,
//! which are stack-based bytecodes used to compute where variables live
//! (in a register, at a memory address, or as a constant value).

use gimli::{Encoding, EndianSlice, Evaluation, EvaluationResult, LittleEndian, Location, Value};

use crate::error::{Error, Result};

/// The result of evaluating a DWARF expression.
#[derive(Debug, Clone)]
pub enum ExprResult {
    /// Value lives at this memory address.
    Address(u64),
    /// Value lives in this DWARF register number.
    Register(u16),
    /// Value is a compile-time constant (stack value).
    Constant(u64),
    /// Variable was optimized out.
    OptimizedOut,
    /// Multiple pieces compose the value.
    Pieces(Vec<ExprPiece>),
}

/// One piece of a multi-piece DWARF expression result.
#[derive(Debug, Clone)]
pub struct ExprPiece {
    pub location: ExprResult,
    pub size_in_bits: u64,
    pub bit_offset: u64,
}

/// Context needed to evaluate DWARF expressions.
pub struct EvalContext<'a> {
    /// Current register values: (DWARF register number, value).
    pub registers: &'a [(u16, u64)],
    /// Canonical Frame Address (from CFI/unwinder).
    pub cfa: u64,
    /// Frame base address (from DW_AT_frame_base of the enclosing function).
    pub frame_base: Option<u64>,
    /// Callback to read tracee memory.
    pub read_memory: &'a dyn Fn(u64, usize) -> Result<Vec<u8>>,
}

impl<'a> EvalContext<'a> {
    fn register_value(&self, reg: gimli::Register) -> Option<u64> {
        let num = reg.0 as u16;
        self.registers.iter().find(|(r, _)| *r == num).map(|(_, v)| *v)
    }
}

/// Evaluate a DWARF expression.
///
/// The expression bytes are interpreted as a stack-based program that
/// computes a location (memory address, register, or constant).
pub fn evaluate(
    expr_bytes: &[u8],
    encoding: Encoding,
    ctx: &EvalContext<'_>,
) -> Result<ExprResult> {
    let slice = EndianSlice::new(expr_bytes, LittleEndian);
    let mut eval = Evaluation::new_in(slice, encoding);
    eval.set_initial_value(0);

    let mut result = eval.evaluate()
        .map_err(|e| Error::Other(format!("DWARF eval start: {}", e)))?;

    loop {
        match result {
            EvaluationResult::Complete => break,

            EvaluationResult::RequiresRegister { register, base_type: _ } => {
                let val = ctx.register_value(register).ok_or_else(|| {
                    Error::Other(format!(
                        "DWARF expr needs register {} but not available",
                        register.0
                    ))
                })?;
                result = eval.resume_with_register(Value::Generic(val))
                    .map_err(|e| Error::Other(format!("DWARF eval register: {}", e)))?;
            }

            EvaluationResult::RequiresFrameBase => {
                let fb = ctx.frame_base.ok_or_else(|| {
                    Error::Other("DWARF expr needs frame base but not available".into())
                })?;
                result = eval.resume_with_frame_base(fb)
                    .map_err(|e| Error::Other(format!("DWARF eval frame_base: {}", e)))?;
            }

            EvaluationResult::RequiresMemory { address, size, .. } => {
                let data = (ctx.read_memory)(address, size as usize)?;
                let val = read_bytes_as_u64(&data);
                result = eval.resume_with_memory(Value::Generic(val))
                    .map_err(|e| Error::Other(format!("DWARF eval memory: {}", e)))?;
            }

            EvaluationResult::RequiresCallFrameCfa => {
                result = eval.resume_with_call_frame_cfa(ctx.cfa)
                    .map_err(|e| Error::Other(format!("DWARF eval CFA: {}", e)))?;
            }

            EvaluationResult::RequiresTls { .. } => {
                return Err(Error::Other("DWARF TLS variables not supported".into()));
            }

            EvaluationResult::RequiresAtLocation { .. } => {
                return Err(Error::Other("DWARF DW_OP_call* not supported".into()));
            }

            EvaluationResult::RequiresRelocatedAddress(addr) => {
                // For non-PIE or already-relocated addresses, pass through.
                result = eval.resume_with_relocated_address(addr)
                    .map_err(|e| Error::Other(format!("DWARF eval reloc: {}", e)))?;
            }

            EvaluationResult::RequiresIndexedAddress { .. } => {
                return Err(Error::Other(
                    "DWARF indexed addresses (split DWARF) not supported".into(),
                ));
            }

            EvaluationResult::RequiresBaseType(_) => {
                return Err(Error::Other(
                    "DWARF typed expressions not supported".into(),
                ));
            }

            EvaluationResult::RequiresEntryValue(_) => {
                return Err(Error::Other(
                    "DWARF DW_OP_entry_value not supported".into(),
                ));
            }

            EvaluationResult::RequiresParameterRef(_) => {
                return Err(Error::Other(
                    "DWARF DW_OP_GNU_parameter_ref not supported".into(),
                ));
            }
        }
    }

    // Convert gimli pieces to our result type
    let pieces = eval.result();
    if pieces.is_empty() {
        return Ok(ExprResult::OptimizedOut);
    }

    if pieces.len() == 1 && pieces[0].bit_offset.is_none() {
        return Ok(convert_location(&pieces[0].location));
    }

    // Multi-piece result
    let expr_pieces = pieces
        .iter()
        .map(|p| ExprPiece {
            location: convert_location(&p.location),
            size_in_bits: p.size_in_bits.unwrap_or(0),
            bit_offset: p.bit_offset.unwrap_or(0),
        })
        .collect();
    Ok(ExprResult::Pieces(expr_pieces))
}

fn convert_location(loc: &Location<EndianSlice<'_, LittleEndian>>) -> ExprResult {
    match loc {
        Location::Address { address } => ExprResult::Address(*address),
        Location::Register { register } => ExprResult::Register(register.0 as u16),
        Location::Value { value } => match value {
            Value::Generic(v) => ExprResult::Constant(*v),
            Value::I8(v) => ExprResult::Constant(*v as u64),
            Value::U8(v) => ExprResult::Constant(*v as u64),
            Value::I16(v) => ExprResult::Constant(*v as u64),
            Value::U16(v) => ExprResult::Constant(*v as u64),
            Value::I32(v) => ExprResult::Constant(*v as u64),
            Value::U32(v) => ExprResult::Constant(*v as u64),
            Value::I64(v) => ExprResult::Constant(*v as u64),
            Value::U64(v) => ExprResult::Constant(*v),
            Value::F32(v) => ExprResult::Constant((*v).to_bits() as u64),
            Value::F64(v) => ExprResult::Constant((*v).to_bits()),
        },
        Location::Empty => ExprResult::OptimizedOut,
        _ => ExprResult::OptimizedOut,
    }
}

/// Read up to 8 bytes as a little-endian u64.
fn read_bytes_as_u64(data: &[u8]) -> u64 {
    let mut buf = [0u8; 8];
    let len = data.len().min(8);
    buf[..len].copy_from_slice(&data[..len]);
    u64::from_le_bytes(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_encoding() -> Encoding {
        Encoding {
            address_size: 8,
            format: gimli::Format::Dwarf64,
            version: 4,
        }
    }

    fn null_read_memory(_addr: u64, _len: usize) -> Result<Vec<u8>> {
        Ok(vec![0; 8])
    }

    #[test]
    fn eval_simple_addr() {
        // DW_OP_addr followed by 8-byte little-endian address
        let bytes = [
            0x03, // DW_OP_addr
            0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x1000
        ];
        let ctx = EvalContext {
            registers: &[],
            cfa: 0,
            frame_base: None,
            read_memory: &null_read_memory,
        };
        let result = evaluate(&bytes, test_encoding(), &ctx).unwrap();
        match result {
            ExprResult::Address(addr) => assert_eq!(addr, 0x1000),
            other => panic!("expected Address, got {:?}", other),
        }
    }

    #[test]
    fn eval_fbreg() {
        // DW_OP_fbreg with SLEB128 offset -16 (0x70)
        let bytes = [
            0x91, // DW_OP_fbreg
            0x70, // SLEB128 -16
        ];
        let ctx = EvalContext {
            registers: &[],
            cfa: 0,
            frame_base: Some(0x7fff0100),
            read_memory: &null_read_memory,
        };
        let result = evaluate(&bytes, test_encoding(), &ctx).unwrap();
        match result {
            ExprResult::Address(addr) => assert_eq!(addr, 0x7fff0100_u64.wrapping_sub(16)),
            other => panic!("expected Address, got {:?}", other),
        }
    }

    #[test]
    fn eval_reg() {
        // DW_OP_reg0 (register 0 = rax in x86_64 DWARF)
        let bytes = [0x50]; // DW_OP_reg0
        let ctx = EvalContext {
            registers: &[(0, 42)],
            cfa: 0,
            frame_base: None,
            read_memory: &null_read_memory,
        };
        let result = evaluate(&bytes, test_encoding(), &ctx).unwrap();
        match result {
            ExprResult::Register(reg) => assert_eq!(reg, 0),
            other => panic!("expected Register, got {:?}", other),
        }
    }

    #[test]
    fn eval_lit_plus_stack_value() {
        // DW_OP_lit5 + DW_OP_stack_value
        let bytes = [
            0x35, // DW_OP_lit5
            0x9f, // DW_OP_stack_value
        ];
        let ctx = EvalContext {
            registers: &[],
            cfa: 0,
            frame_base: None,
            read_memory: &null_read_memory,
        };
        let result = evaluate(&bytes, test_encoding(), &ctx).unwrap();
        match result {
            ExprResult::Constant(val) => assert_eq!(val, 5),
            other => panic!("expected Constant(5), got {:?}", other),
        }
    }

    #[test]
    fn eval_breg_offset() {
        // DW_OP_breg7 (rbp/rsp) + SLEB128 offset +8
        let bytes = [
            0x77, // DW_OP_breg7 (register 7 = rsp on x86_64)
            0x08, // SLEB128 +8
        ];
        let ctx = EvalContext {
            registers: &[(7, 0x7fff0000)],
            cfa: 0,
            frame_base: None,
            read_memory: &null_read_memory,
        };
        let result = evaluate(&bytes, test_encoding(), &ctx).unwrap();
        match result {
            ExprResult::Address(addr) => assert_eq!(addr, 0x7fff0008),
            other => panic!("expected Address, got {:?}", other),
        }
    }

    #[test]
    fn read_bytes_as_u64_various_sizes() {
        assert_eq!(read_bytes_as_u64(&[0x42]), 0x42);
        assert_eq!(read_bytes_as_u64(&[0x01, 0x02]), 0x0201);
        assert_eq!(
            read_bytes_as_u64(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]),
            0x0807060504030201
        );
    }
}

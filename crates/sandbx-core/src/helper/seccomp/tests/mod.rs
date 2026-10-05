//! Unit tests for the syscall filter, split by what they gate on; this module holds
//! the `eval` interpreter they are all read through, and its own tests.
//!
//! Kernel-free — the program is evaluated here rather than installed, so these run
//! anywhere. `tests/enforcement_syscalls.rs` is where a live kernel refuses a call.

use super::*;
use crate::SandboxPolicy;

mod arch;
mod denylist;
mod namespaces;
mod sockets;

// The three verdicts this filter can produce, taken from `libc` and not from
// `u32::from(SeccompAction::…)`, which would leave expected and actual sharing a
// source. These are kernel ABI and cannot move with the thing under test.
const ALLOW: u32 = libc::SECCOMP_RET_ALLOW;
const EPERM: u32 = libc::SECCOMP_RET_ERRNO | libc::EPERM as u32;
const ENOSYS: u32 = libc::SECCOMP_RET_ERRNO | libc::ENOSYS as u32;
const KILL: u32 = libc::SECCOMP_RET_KILL_PROCESS;

// The classic-BPF opcodes `compiled_filter`'s program is built from, composed from
// `libc`'s field constants rather than written as folded literals.
//
// `BPF_LD`, `BPF_W`, `BPF_K` and `BPF_JA` are all `0x00`, so composing cannot catch a
// dropped zero-valued term. It does catch a *wrong* term — `BPF_LDX` is `0x01`,
// `BPF_X` is `0x08` — which produces a value no instruction matches, so `eval` hits
// its panic arm loudly instead of mis-evaluating.
//
// This set is closed only as long as seccompiler's codegen is; see `eval`.
const LD_W_ABS: u16 = (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16;
const ALU_AND_K: u16 = (libc::BPF_ALU | libc::BPF_AND | libc::BPF_K) as u16;
const JA: u16 = (libc::BPF_JMP | libc::BPF_JA) as u16;
const JEQ_K: u16 = (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16;
const JGT_K: u16 = (libc::BPF_JMP | libc::BPF_JGT | libc::BPF_K) as u16;
const JGE_K: u16 = (libc::BPF_JMP | libc::BPF_JGE | libc::BPF_K) as u16;
const RET_K: u16 = (libc::BPF_RET | libc::BPF_K) as u16;

/// Every opcode [`eval`] implements, for the structural check in [`denylist`].
const KNOWN_OPCODES: &[u16] = &[LD_W_ABS, ALU_AND_K, JA, JEQ_K, JGT_K, JGE_K, RET_K];

// `AUDIT_ARCH_*` for the architecture the test runs on: the `EM_*` machine number
// from `linux/elf-em.h`, or'd with `__AUDIT_ARCH_64BIT` and `__AUDIT_ARCH_LE` from
// `linux/audit.h`. Transcribed because `libc` does not export these and seccompiler
// keeps its own copies private (`backend/bpf.rs`).
//
// The transcription cannot pass silently: the filter's first act is to compare
// `seccomp_data.arch` and kill on a mismatch, so a wrong value turns every verdict
// these modules take into a loud failure, and
// `the_filter_gates_on_the_arch_this_test_models` names the drift.
#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH: u32 = 62 | 0x8000_0000 | 0x4000_0000;
#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH: u32 = 183 | 0x8000_0000 | 0x4000_0000;
#[cfg(target_arch = "riscv64")]
const AUDIT_ARCH: u32 = 243 | 0x8000_0000 | 0x4000_0000;
#[cfg(not(any(
    target_arch = "x86_64",
    target_arch = "aarch64",
    target_arch = "riscv64"
)))]
compile_error!(
    "this architecture needs its AUDIT_ARCH_* from linux/audit.h here, or the \
     filter's arch gate kills every syscall the tests evaluate"
);

#[cfg(target_endian = "big")]
compile_error!(
    "the seccomp_data word model in `seccomp_data` below assumes little-endian; \
     see the note there on why the load is native-endian"
);

/// Build one instruction. seccompiler's `bpf_stmt`/`bpf_jump` are private, so
/// `sock_filter` is composed directly.
fn insn(code: u16, jt: u8, jf: u8, k: u32) -> seccompiler::sock_filter {
    seccompiler::sock_filter { code, jt, jf, k }
}

/// `struct seccomp_data` as the sixteen 32-bit words a `BPF_LD | BPF_W | BPF_ABS`
/// instruction addresses.
///
/// 64 bytes: `nr` at 0, `arch` at 4, `instruction_pointer` at 8, `args[6]` at 16
/// (`seccompiler/backend/bpf.rs`). Each argument's *least* significant half sits at
/// the lower offset, so word `4 + 2 * i` is `args[i]`'s low word and `5 + 2 * i` its
/// high word.
///
/// Little-endian, and worth pinning, because it is the claim a reader is most likely
/// to "fix" wrongly: in *socket* classic BPF an absolute word load is a big-endian
/// packet read, but in *seccomp* it is not. `seccomp_check_filter()` rewrites every
/// `BPF_LD | BPF_W | BPF_ABS` to `BPF_LDX | BPF_MEM | BPF_W` before the program runs,
/// making it a plain native-endian field read out of the struct. A `[u32; 16]` is
/// therefore the right model — and only because every architecture seccompiler
/// supports is little-endian.
fn seccomp_data(nr: libc::c_long, args: [u64; 6]) -> [u32; 16] {
    let mut data = [0u32; 16];

    // Not `u32::try_from(nr).unwrap()`: `nr` is a signed `int`, every comparison the
    // filter makes against it is `jeq` and so sign-agnostic, and `syscall(-1)` is a
    // legal thing for a process to pass.
    data[0] = nr as u32;
    data[1] = AUDIT_ARCH;
    // `instruction_pointer` stays zero; no rule sandbx builds looks at it.
    for (i, arg) in args.iter().enumerate() {
        data[4 + 2 * i] = *arg as u32;
        data[5 + 2 * i] = (*arg >> 32) as u32;
    }

    data
}

/// Run `program` over `data` and return the verdict it yields.
///
/// Evaluating rather than asserting over the program's instruction *layout*: the
/// layout is seccompiler's codegen rather than ABI, and a layout check sees that
/// instructions exist, not that control flow reaches them, so a wrong jump offset
/// passes.
///
/// The codegen coupling is relocated here, not eliminated: the opcode set above is
/// closed only as long as seccompiler's codegen is. What keeps that honest is the
/// panic at the bottom — an unimplemented opcode must never produce a verdict, because
/// a mis-evaluation returning `ALLOW` would be worse than the layout coupling it
/// replaces.
///
/// Takes `BpfProgramRef` rather than `&BpfProgram`, which is a `&Vec` and trips
/// `clippy::ptr_arg`; it is also what `apply_filter` takes.
///
/// This loop cannot spin, so it carries no guard: every arm derives its target as
/// `pc + 1 + <unsigned offset>`, so `pc` strictly increases and the `get` at the top
/// panics by name once it reaches `program.len()`. An arm that *could* jump backwards
/// would have to subtract — which is where to put a check if a future opcode needs
/// one.
fn eval(program: seccompiler::BpfProgramRef<'_>, data: &[u32; 16]) -> u32 {
    let mut acc = 0u32;
    let mut pc = 0usize;

    loop {
        let insn = program.get(pc).unwrap_or_else(|| {
            panic!(
                "control flow ran off the end of the program at pc {pc} of {}",
                program.len()
            )
        });
        let next = pc + 1;

        // Compared with `==`, not matched: in a pattern, an uppercase path that fails
        // to resolve to a constant becomes a fresh binding rather than an error, so
        // the first arm would swallow every opcode and the only signal would be
        // `unreachable_patterns` — a warning. `==` makes that a type error.
        let target = if insn.code == LD_W_ABS {
            let offset = usize::try_from(insn.k)
                .unwrap_or_else(|_| panic!("load offset {} does not fit a usize", insn.k));
            // `seccomp_check_filter()` refuses a filter whose absolute load is
            // unaligned or outside `struct seccomp_data`; restated here.
            assert_eq!(
                offset % 4,
                0,
                "unaligned load at pc {pc}; the kernel would refuse this filter: {insn:?}"
            );
            acc = *data.get(offset / 4).unwrap_or_else(|| {
                panic!(
                    "the load at pc {pc} reads byte {offset}, outside the 64-byte \
                     seccomp_data; the kernel would refuse this filter: {insn:?}"
                )
            });
            next
        } else if insn.code == ALU_AND_K {
            acc &= insn.k;
            next
        } else if insn.code == JA {
            // The offset is in `k`, not in `jt`.
            next + usize::try_from(insn.k)
                .unwrap_or_else(|_| panic!("jump offset {} does not fit a usize", insn.k))
        } else if insn.code == JEQ_K {
            next + usize::from(if acc == insn.k { insn.jt } else { insn.jf })
        } else if insn.code == JGT_K {
            // Unsigned, as classic BPF specifies; both sides are `u32`, so this is the
            // comparison the kernel makes.
            next + usize::from(if acc > insn.k { insn.jt } else { insn.jf })
        } else if insn.code == JGE_K {
            next + usize::from(if acc >= insn.k { insn.jt } else { insn.jf })
        } else if insn.code == RET_K {
            return insn.k;
        } else {
            panic!(
                "seccompiler emitted opcode {:#x} at pc {pc}, which this interpreter \
                 does not implement. It was verified against seccompiler 0.5.0 \
                 `backend/bpf.rs`, `condition.rs`, `rule.rs` and `filter.rs`. Re-read \
                 those and extend `eval` — do not add an arm that returns a default \
                 verdict: {insn:?}",
                insn.code
            )
        };

        pc = target;
    }
}

/// The verdict for `nr` called with all-zero arguments.
fn verdict(program: seccompiler::BpfProgramRef<'_>, nr: libc::c_long) -> u32 {
    eval(program, &seccomp_data(nr, [0; 6]))
}

/// The verdict for `nr` called with `args`.
///
/// Every test goes through this rather than touching a word index, because `data[4]`
/// is `args[0]`'s low half while `data[5]` is its high half and `data[6]` is `args[1]`
/// — an off-by-one would silently assert about the wrong field.
fn verdict_with_args(
    program: seccompiler::BpfProgramRef<'_>,
    nr: libc::c_long,
    args: [u64; 6],
) -> u32 {
    eval(program, &seccomp_data(nr, args))
}

/// The verdict for `nr` as seen from a process reporting `arch`.
fn verdict_from_arch(program: seccompiler::BpfProgramRef<'_>, nr: libc::c_long, arch: u32) -> u32 {
    let mut data = seccomp_data(nr, [0; 6]);
    data[1] = arch;
    eval(program, &data)
}

/// The verdict for `socket(domain, 0, 0)`.
///
/// `domain` is wider than the `int` the kernel reads, so a test can put something in
/// the half the comparison must ignore.
fn socket_verdict(program: seccompiler::BpfProgramRef<'_>, domain: u64) -> u32 {
    verdict_with_args(program, libc::SYS_socket, [domain, 0, 0, 0, 0, 0])
}

/// The verdict for `socket(domain, socket_type, 0)`.
///
/// Both arguments are wider than the `int`s the kernel reads, so a test can put something
/// in the halves and the flag bits the comparisons must ignore.
fn typed_socket_verdict(
    program: seccompiler::BpfProgramRef<'_>,
    domain: u64,
    socket_type: u64,
) -> u32 {
    verdict_with_args(program, libc::SYS_socket, [domain, socket_type, 0, 0, 0, 0])
}

/// [`eval`] is itself untested code whose failure mode is the silent pass, so these
/// cases cover the classic mis-implementations over hand-written programs rather than
/// the compiled filter.
///
/// Only `JGT` is unreachable from the installed filters now: the `clone` rules are
/// `MaskedEq`, which seccompiler compiles to `ALU|AND` plus `jeq`, and `x32_gate`
/// hand-writes a `JGE`. It is implemented anyway, because the alternative is an arm
/// that panics on a program seccompiler can legitimately emit.
#[test]
fn eval_implements_the_opcodes_seccompiler_can_emit() {
    // Every program loads word 0, `nr`, so the case's `nr` is what the comparison
    // sees. `jt`, `jf` and `JA`'s `k` are offsets from the *following* instruction,
    // so 1 skips exactly one.
    let cases: &[(&str, Vec<seccompiler::sock_filter>, libc::c_long, u32)] = &[
        (
            "jgt is strict, so an equal value does not take the greater branch",
            vec![
                insn(LD_W_ABS, 0, 0, 0),
                insn(JGT_K, 1, 0, 5),
                insn(RET_K, 0, 0, ALLOW),
                insn(RET_K, 0, 0, EPERM),
            ],
            5,
            ALLOW,
        ),
        (
            "jgt does fire on a greater value",
            vec![
                insn(LD_W_ABS, 0, 0, 0),
                insn(JGT_K, 1, 0, 5),
                insn(RET_K, 0, 0, ALLOW),
                insn(RET_K, 0, 0, EPERM),
            ],
            6,
            EPERM,
        ),
        (
            "jge takes the branch on an equal value",
            vec![
                insn(LD_W_ABS, 0, 0, 0),
                insn(JGE_K, 1, 0, 5),
                insn(RET_K, 0, 0, ALLOW),
                insn(RET_K, 0, 0, EPERM),
            ],
            5,
            EPERM,
        ),
        (
            // An `i32` interpretation inverts this one: -1 is not > 1 signed, but
            // 0xffff_ffff is unsigned, and the kernel compares unsigned.
            "the comparison is unsigned",
            vec![
                insn(LD_W_ABS, 0, 0, 0),
                insn(JGT_K, 1, 0, 1),
                insn(RET_K, 0, 0, ALLOW),
                insn(RET_K, 0, 0, EPERM),
            ],
            -1,
            EPERM,
        ),
        (
            // Without the mask 0x19 does not equal 0x10 and this falls to ALLOW,
            // so the case discriminates.
            "alu-and masks the accumulator before the comparison",
            vec![
                insn(LD_W_ABS, 0, 0, 0),
                insn(ALU_AND_K, 0, 0, 0xf0),
                insn(JEQ_K, 1, 0, 0x10),
                insn(RET_K, 0, 0, ALLOW),
                insn(RET_K, 0, 0, EPERM),
            ],
            0x19,
            EPERM,
        ),
        (
            // Reading the offset from `jt` (0) instead of `k` lands on ALLOW, so
            // the case discriminates.
            "an unconditional jump takes its offset from k",
            vec![
                insn(LD_W_ABS, 0, 0, 0),
                insn(JA, 0, 0, 1),
                insn(RET_K, 0, 0, ALLOW),
                insn(RET_K, 0, 0, EPERM),
            ],
            0,
            EPERM,
        ),
    ];

    for (property, program, nr, expected) in cases {
        assert_eq!(
            eval(program, &seccomp_data(*nr, [0; 6])),
            *expected,
            "the interpreter is wrong about {property}, so every verdict it \
             reports below is unreliable"
        );
    }
}

/// `expected` is not optional: without it the test also passes on the off-the-end
/// panic, on the alignment assertion, or on an `unwrap` elsewhere in the body — any of
/// which would leave the panic arm itself unexercised. The opcode is one seccompiler
/// could plausibly grow into (`BPF_LDX | BPF_MEM | BPF_W`, a scratch-memory load)
/// rather than a value no BPF dialect uses.
#[test]
#[should_panic(expected = "does not implement")]
fn eval_refuses_an_opcode_it_does_not_implement() {
    let ldx_mem_w = (libc::BPF_LDX | libc::BPF_MEM | libc::BPF_W) as u16;

    eval(
        &[insn(ldx_mem_w, 0, 0, 0)],
        &seccomp_data(libc::SYS_getpid, [0; 6]),
    );
}

/// Nothing else here would notice if [`seccomp_data`] misplaced a field: every other
/// test passes all-zero arguments or a value in `args[0]` alone, and the array starts
/// zeroed — so the stride `4 + 2 * i` could map arguments 1 through 5 onto each
/// other's words with all of them still passing.
///
/// That matters for the next rule rather than today's: sandbx gates only on `socket`'s
/// argument 0, but `clone`'s flags, `socket`'s `type` and an `ioctl` request all sit
/// above index zero (#118), and a rule on one of those would be evaluated against the
/// wrong word.
///
/// Each half is checked separately, with distinct values, because an argument written
/// as one 64-bit store to the right *pair* in the wrong order would otherwise pass.
#[test]
fn seccomp_data_puts_each_field_where_the_kernel_does() {
    let args = std::array::from_fn::<u64, 6, _>(|i| {
        let i = i as u64;
        (0x2000_0000 | i) << 32 | (0x1000_0000 | i)
    });
    let data = seccomp_data(libc::SYS_socket, args);

    // Byte offsets read off `struct seccomp_data`'s definition rather than off
    // `seccomp_data`'s own arithmetic: `nr` @0, `arch` @4, the 64-bit
    // `instruction_pointer` @8, `args[6]` @16.
    let mut fields = vec![
        ("nr".to_owned(), 0, libc::SYS_socket as u32),
        ("arch".to_owned(), 4, AUDIT_ARCH),
        ("instruction_pointer low".to_owned(), 8, 0),
        ("instruction_pointer high".to_owned(), 12, 0),
    ];
    for (i, arg) in args.iter().enumerate() {
        fields.push((format!("args[{i}] low"), 16 + 8 * i, *arg as u32));
        fields.push((format!("args[{i}] high"), 20 + 8 * i, (*arg >> 32) as u32));
    }

    for (field, offset, expected) in fields {
        // `eval` has no way to return the accumulator — `BPF_RET | BPF_A` is not an
        // opcode seccompiler emits — so the comparison is the program: load the
        // field, return `ALLOW` only if it holds what it should.
        let program = [
            insn(LD_W_ABS, 0, 0, u32::try_from(offset).unwrap()),
            insn(JEQ_K, 0, 1, expected),
            insn(RET_K, 0, 0, ALLOW),
            insn(RET_K, 0, 0, EPERM),
        ];

        assert_eq!(
            eval(&program, &data),
            ALLOW,
            "a load at byte {offset} does not read {field}, so `seccomp_data` \
             does not model the kernel's struct and a rule on that field would \
             be evaluated against the wrong word"
        );
    }
}

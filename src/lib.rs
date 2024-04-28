// SPDX-License-Identifier: BSD-3-Clause
// Copyright(c) 2023-2024 Intel Corporation.

#![no_std]
#![allow(dead_code)]
#![allow(unused_variables)]

extern crate alloc;

mod asm;
pub mod tdcall;
pub mod tdvmcall;

pub use self::tdcall::{get_veinfo, TdxVirtualExceptionType};
pub use self::tdvmcall::print;
use core::sync::atomic::{AtomicBool, Ordering::Relaxed};
use raw_cpuid::{native_cpuid::cpuid_count, CpuIdResult};
use tdcall::{InitError, TdgVpInfo};

static TDX_ENABLED: AtomicBool = AtomicBool::new(false);

#[inline(always)]
pub fn tdx_is_enabled() -> bool {
    TDX_ENABLED.load(Relaxed)
}

pub fn init_tdx() -> Result<TdgVpInfo, InitError> {
    check_tdx_guest()?;
    Ok(tdcall::get_tdinfo()?)
}

fn check_tdx_guest() -> Result<(), InitError> {
    const TDX_CPUID_LEAF_ID: u64 = 0x21;
    let cpuid_leaf = cpuid_count(0, 0).eax as u64;
    if cpuid_leaf < TDX_CPUID_LEAF_ID {
        return Err(InitError::TdxCpuLeafIdError);
    }
    let cpuid_result: CpuIdResult = cpuid_count(TDX_CPUID_LEAF_ID as u32, 0);
    if &cpuid_result.ebx.to_ne_bytes() != b"Inte"
        || &cpuid_result.edx.to_ne_bytes() != b"lTDX"
        || &cpuid_result.ecx.to_ne_bytes() != b"    "
    {
        return Err(InitError::TdxVendorIdError);
    }
    Ok(())
}

use rand_core::{OsRng, RngCore};

const TDX_CPUID_LEAF_ID: u64 = 0x21;
const REPORT_DATA_SIZE: usize = 64;
const TDX_REPORT_SIZE: usize = 1024;
const TDX_UUID_SIZE: usize = 16;
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::mem;
use tdcall::get_report;

pub const SHARED_BIT: u8 = 51;
pub const SHARED_MASK: u64 = 1u64 << SHARED_BIT;

#[repr(align(64))]
struct ReportDataWapper {
    report_data: [u8; REPORT_DATA_SIZE],
}

#[repr(align(1024))]
struct TdxReportWapper {
    tdx_report: [u8; TDX_REPORT_SIZE],
}

// Application level code
pub fn generate_quote() {
    let wrapped_report = TdxReportWapper {
        tdx_report: [0; TDX_REPORT_SIZE],
    };
    let mut wrapped_data = ReportDataWapper {
        report_data: [0; REPORT_DATA_SIZE],
    };
    OsRng.fill_bytes(&mut wrapped_data.report_data);
    // tdx_att_get_report(&wrapped_data.report_data, &wrapped_report.tdx_report).unwrap();
    serial_println!("Get TDX report data success.");

    // uuid
    let selected_att_key_id = [0; TDX_UUID_SIZE];
    // let quote = tdx_att_get_quote(
    //     &wrapped_report.tdx_report,
    //     selected_att_key_id.as_ptr() as u64,
    // )
    // .unwrap();
    serial_println!("ATT key id: {:?}", selected_att_key_id);
    // serial_println!("TDX quote data: {:?}", quote);
    serial_println!("Successfully get the TD Quote.");
    // std::fs::write("quote.dat", quote).expect("Unable to write quote file.");
}

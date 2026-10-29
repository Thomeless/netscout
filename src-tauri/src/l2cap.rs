// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Tomáš Nesrsta
//! Minimální pasivní zachytávání rámců přes Npcap/WinPcap. wpcap.dll se načítá za běhu,
//! takže aplikace se přeloží i spustí bez Npcap SDK; bez Npcap jen nefunguje CDP/LLDP.

use libloading::Library;
use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::net::Ipv4Addr;
use std::sync::Arc;

const ERRBUF: usize = 256;

#[repr(C)]
struct PcapIf {
    next: *mut PcapIf,
    name: *mut c_char,
    description: *mut c_char,
    addresses: *mut PcapAddr,
    flags: u32,
}

#[repr(C)]
struct PcapAddr {
    next: *mut PcapAddr,
    addr: *mut SockAddr,
    netmask: *mut SockAddr,
    broadaddr: *mut SockAddr,
    dstaddr: *mut SockAddr,
}

#[repr(C)]
struct SockAddr {
    family: u16,
    port: u16,
    ip: [u8; 4],
}

#[repr(C)]
struct PktHdr {
    ts_sec: i32,
    ts_usec: i32,
    caplen: u32,
    len: u32,
}

#[repr(C)]
struct BpfProgram {
    len: u32,
    insns: *mut c_void,
}

type FindAllDevs = unsafe extern "C" fn(*mut *mut PcapIf, *mut c_char) -> c_int;
type FreeAllDevs = unsafe extern "C" fn(*mut PcapIf);
type OpenLive = unsafe extern "C" fn(*const c_char, c_int, c_int, c_int, *mut c_char) -> *mut c_void;
type Compile = unsafe extern "C" fn(*mut c_void, *mut BpfProgram, *const c_char, c_int, u32) -> c_int;
type SetFilter = unsafe extern "C" fn(*mut c_void, *mut BpfProgram) -> c_int;
type FreeCode = unsafe extern "C" fn(*mut BpfProgram);
type NextEx = unsafe extern "C" fn(*mut c_void, *mut *mut PktHdr, *mut *const u8) -> c_int;
type Close = unsafe extern "C" fn(*mut c_void);
type GetErr = unsafe extern "C" fn(*mut c_void) -> *const c_char;

pub struct Api {
    findalldevs: FindAllDevs,
    freealldevs: FreeAllDevs,
    open_live: OpenLive,
    compile: Compile,
    setfilter: SetFilter,
    freecode: FreeCode,
    next_ex: NextEx,
    close: Close,
    geterr: GetErr,
    _lib: Library,
}

pub struct Device {
    pub name: String,
    pub addrs: Vec<Ipv4Addr>,
}

impl Api {
    pub fn load() -> Result<Arc<Api>, String> {
        let lib = ["wpcap.dll", r"C:\Windows\System32\Npcap\wpcap.dll"]
            .iter()
            .find_map(|p| unsafe { Library::new(*p).ok() })
            .ok_or("wpcap.dll nenalezena (nainstaluj Npcap)")?;
        macro_rules! sym {
            ($n:literal) => {
                unsafe { *lib.get($n).map_err(|e| format!("wpcap.dll: {e}"))? }
            };
        }
        Ok(Arc::new(Api {
            findalldevs: sym!(b"pcap_findalldevs\0"),
            freealldevs: sym!(b"pcap_freealldevs\0"),
            open_live: sym!(b"pcap_open_live\0"),
            compile: sym!(b"pcap_compile\0"),
            setfilter: sym!(b"pcap_setfilter\0"),
            freecode: sym!(b"pcap_freecode\0"),
            next_ex: sym!(b"pcap_next_ex\0"),
            close: sym!(b"pcap_close\0"),
            geterr: sym!(b"pcap_geterr\0"),
            _lib: lib,
        }))
    }

    pub fn devices(&self) -> Result<Vec<Device>, String> {
        let mut err = [0 as c_char; ERRBUF];
        let mut all: *mut PcapIf = std::ptr::null_mut();
        if unsafe { (self.findalldevs)(&mut all, err.as_mut_ptr()) } != 0 {
            return Err(cstr(err.as_ptr()));
        }
        let mut out = vec![];
        let mut d = all;
        while !d.is_null() {
            let dev = unsafe { &*d };
            let mut addrs = vec![];
            let mut a = dev.addresses;
            while !a.is_null() {
                let ad = unsafe { &*a };
                if !ad.addr.is_null() {
                    let sa = unsafe { &*ad.addr };
                    if sa.family == 2 {
                        addrs.push(Ipv4Addr::from(sa.ip));
                    }
                }
                a = ad.next;
            }
            out.push(Device { name: cstr(dev.name), addrs });
            d = dev.next;
        }
        unsafe { (self.freealldevs)(all) };
        Ok(out)
    }

    /// Otevře zařízení v promiskuitním režimu s BPF filtrem; čtení vyprší po 500 ms.
    pub fn open(self: &Arc<Self>, device: &str, filter: &str) -> Result<Capture, String> {
        let name = CString::new(device).map_err(|e| e.to_string())?;
        let mut err = [0 as c_char; ERRBUF];
        let h = unsafe { (self.open_live)(name.as_ptr(), 2048, 1, 500, err.as_mut_ptr()) };
        if h.is_null() {
            return Err(cstr(err.as_ptr()));
        }
        let cap = Capture { api: self.clone(), handle: h };
        let f = CString::new(filter).map_err(|e| e.to_string())?;
        let mut prog = BpfProgram { len: 0, insns: std::ptr::null_mut() };
        if unsafe { (self.compile)(h, &mut prog, f.as_ptr(), 1, 0xffff_ffff) } != 0 {
            return Err(cap.last_error());
        }
        let rc = unsafe { (self.setfilter)(h, &mut prog) };
        unsafe { (self.freecode)(&mut prog) };
        if rc != 0 {
            return Err(cap.last_error());
        }
        Ok(cap)
    }
}

pub struct Capture {
    api: Arc<Api>,
    handle: *mut c_void,
}

// Handle používá vždy jen jedno vlákno, které capture vlastní.
unsafe impl Send for Capture {}

impl Capture {
    fn last_error(&self) -> String {
        cstr(unsafe { (self.api.geterr)(self.handle) })
    }

    /// Ok(Some(rámec)), Ok(None) při vypršení časového limitu, Err při chybě.
    pub fn next(&mut self) -> Result<Option<Vec<u8>>, String> {
        let mut hdr: *mut PktHdr = std::ptr::null_mut();
        let mut data: *const u8 = std::ptr::null();
        match unsafe { (self.api.next_ex)(self.handle, &mut hdr, &mut data) } {
            1 => {
                let n = unsafe { (*hdr).caplen } as usize;
                Ok(Some(unsafe { std::slice::from_raw_parts(data, n) }.to_vec()))
            }
            0 => Ok(None),
            _ => Err(self.last_error()),
        }
    }
}

impl Drop for Capture {
    fn drop(&mut self) {
        unsafe { (self.api.close)(self.handle) };
    }
}

fn cstr(p: *const c_char) -> String {
    if p.is_null() {
        return String::new();
    }
    unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
}

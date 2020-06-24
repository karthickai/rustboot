#![allow(unsafe_code)]
#![allow(dead_code)]
#![no_main]
#![no_std]

// panic crate
extern crate panic_halt;

// STM32F7 device crate
use crate::hal::{device, prelude::*};
use cortex_m::asm;
use cortex_m_rt::{entry, exception};
use stm32f7xx_hal as hal;
use stm32f7xx_hal::device::{interrupt, SYST};

// To avoid datarace
use core::cell::RefCell;
use cortex_m::interrupt::Mutex;

// stm32-eth driver crate
use stm32_eth::smoltcp::iface::{EthernetInterfaceBuilder, NeighborCache};
use stm32_eth::smoltcp::socket::{SocketSet, TcpSocket, TcpSocketBuffer};
use stm32_eth::smoltcp::time::Instant;
use stm32_eth::smoltcp::wire::{EthernetAddress, IpAddress, IpCidr, Ipv4Address};
use stm32_eth::{Eth, RingEntry};

// Network command
const CMD_ERASE: u32 = 2;
const CMD_WRITE: u32 = 3;
const CMD_BOOT: u32 = 4;

// Network error enum
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Success,
    InvalidAddress,
    LengthNotMultiple4,
    LengthTooLong,
    DataLengthIncorrect,
    EraseError,
    WriteError,
    FlashError,
    NetworkError,
    InternalError,
}

pub type Result<T> = core::result::Result<T, Error>;

// Flash memory sector array
pub const FLASH_SECTOR_ADDRESSES: [u32; 12] = [
    0x0800_0000,
    0x0800_8000,
    0x0801_0000,
    0x0801_8000,
    0x0802_0000,
    0x0804_0000,
    0x0808_0000,
    0x080C_0000,
    0x0810_0000,
    0x0814_0000,
    0x0818_0000,
    0x081C_0000,
];
/// Final valid address in flash
pub const FLASH_END: u32 = 0x081F_FFFF;
pub const FLASH_USER: u32 = 0x0808_0000;
static mut FLASH: Option<device::FLASH> = None;

pub fn init(flash: device::FLASH) {
    unsafe { FLASH = Some(flash) };
}

const SRC_MAC: [u8; 6] = [0x00, 0x00, 0xDE, 0xAD, 0xBE, 0xEF];
static TIME: Mutex<RefCell<u64>> = Mutex::new(RefCell::new(0));
static ETH_PENDING: Mutex<RefCell<bool>> = Mutex::new(RefCell::new(false));

#[entry]
fn main() -> ! {
    let p = device::Peripherals::take().unwrap();
    let mut cp = device::CorePeripherals::take().unwrap();

    setup_systick(&mut cp.SYST); // enable systic peripherals

    let gpioa = p.GPIOA.split();
    let gpiob = p.GPIOB.split();
    let gpioc = p.GPIOC.split();
    let gpiog = p.GPIOG.split();

    let mut led = gpiob.pb7.into_push_pull_output();

    // check the user button to jump user application
    let pushbtn = gpioc.pc13.into_floating_input();
    match pushbtn.is_high() {
        Ok(true) => {}
        Ok(false) => match valid_user_code() {
            Some(_) => boot(&mut cp.SCB),
            None => (),
        },
        _ => unreachable!(),
    };

    // stm32-eth initialisation
    stm32_eth::setup(&p.RCC, &p.SYSCFG);
    stm32_eth::setup_pins(
        gpioa.pa1, gpioa.pa2, gpioa.pa7, gpiob.pb13, gpioc.pc1, gpioc.pc4, gpioc.pc5, gpiog.pg11,
        gpiog.pg13,
    );

    let mut rx_ring: [RingEntry<_>; 8] = Default::default();
    let mut tx_ring: [RingEntry<_>; 2] = Default::default();
    let clocks = p.RCC.constrain().cfgr.freeze();
    let mut eth = Eth::new(
        p.ETHERNET_MAC,
        p.ETHERNET_DMA,
        &mut rx_ring[..],
        &mut tx_ring[..],
        &clocks,
    );
    eth.enable_interrupt();

    let local_addr = Ipv4Address::new(192, 168, 0, 167);
    let ip_addr = IpCidr::new(IpAddress::from(local_addr), 24);
    let mut ip_addrs = [ip_addr];
    let mut neighbor_storage = [None; 16];
    let neighbor_cache = NeighborCache::new(&mut neighbor_storage[..]);
    let ethernet_addr = EthernetAddress(SRC_MAC);
    let mut iface = EthernetInterfaceBuilder::new(&mut eth)
        .ethernet_addr(ethernet_addr)
        .ip_addrs(&mut ip_addrs[..])
        .neighbor_cache(neighbor_cache)
        .finalize();

    let mut server_rx_buffer = [0; 2048];
    let mut server_tx_buffer = [0; 2048];
    let server_socket = TcpSocket::new(
        TcpSocketBuffer::new(&mut server_rx_buffer[..]),
        TcpSocketBuffer::new(&mut server_tx_buffer[..]),
    );
    let mut sockets_storage = [None, None];
    let mut sockets = SocketSet::new(&mut sockets_storage[..]);
    let server_handle = sockets.add(server_socket);
    // turn blue led on
    led.set_high().expect("GPIO can never fail");
    //init the flash peripheral
    init(p.FLASH);

    loop {
        let time: u64 = cortex_m::interrupt::free(|cs| *TIME.borrow(cs).borrow());
        cortex_m::interrupt::free(|cs| {
            let mut eth_pending = ETH_PENDING.borrow(cs).borrow_mut();
            *eth_pending = false;
        });
        match iface.poll(&mut sockets, Instant::from_millis(time as i64)) {
            Ok(true) => {
                let mut socket = sockets.get::<TcpSocket>(server_handle);
                if !socket.is_open() {
                    socket.listen(8080).unwrap();
                }
                if !socket.may_recv() && socket.may_send() {
                    socket.close();
                }
                if socket.can_recv() {
                    let mut cmd = [0u8; 4];

                    socket.recv_slice(&mut cmd[..]).ok();
                    let cmd = u32::from_le_bytes(cmd);

                    match cmd {
                        CMD_ERASE => cmd_erase(&mut socket),
                        CMD_WRITE => {
                            cmd_write(&mut socket);
                        }
                        CMD_BOOT => {
                            let aircr = 0xE000ED0C as *mut u32;
                            unsafe { *aircr = (0x5FA << 16) | (1 << 2) };
                        }
                        _ => (),
                    };
                    socket.close();
                }
            }
            Ok(false) => {
                // Sleep if no ethernet work is pending
                cortex_m::interrupt::free(|cs| {
                    let eth_pending = ETH_PENDING.borrow(cs).borrow_mut();
                    if !*eth_pending {
                        asm::wfi();
                        // Awaken by interrupt
                    }
                });
            }
            Err(_e) =>
                // Ignore malformed packets
                {}
        }
    }
}

fn setup_systick(syst: &mut SYST) {
    syst.set_reload(SYST::get_ticks_per_10ms() / 10);
    syst.enable_counter();
    syst.enable_interrupt();
}

#[exception]
fn SysTick() {
    cortex_m::interrupt::free(|cs| {
        let mut time = TIME.borrow(cs).borrow_mut();
        *time += 1;
    })
}

#[interrupt]
fn ETH() {
    cortex_m::interrupt::free(|cs| {
        let mut eth_pending = ETH_PENDING.borrow(cs).borrow_mut();
        *eth_pending = true;
    });

    // Clear interrupt flags
    let p = unsafe { device::Peripherals::steal() };
    stm32_eth::eth_interrupt_handler(&p.ETHERNET_DMA);
}

/// Jump to the user application code
fn boot(scb: &mut cortex_m::peripheral::SCB) {
    unsafe {
        // let sp: u32 = *(FLASH_USER as *const u32);
        let rv: usize = *((FLASH_USER + 4) as *const usize);
        scb.vtor.write(FLASH_USER);
        // cortex_m::register::msp::write(sp);
        let function = core::mem::transmute::<usize, extern "C" fn() -> !>(rv);
        function();
    }
}

/// check the valid user code in flash user memory address
pub fn valid_user_code() -> Option<u32> {
    let reset_vector: u32 = unsafe { *((FLASH_USER + 4) as *const u32) };
    if reset_vector >= FLASH_USER && reset_vector <= FLASH_END {
        Some(FLASH_USER)
    } else {
        None
    }
}

/// Read an address and length from the socket
fn read_adr_len(socket: &mut TcpSocket) -> (u32, usize) {
    let mut adr = [0u8; 4];
    let mut len = [0u8; 4];
    socket.recv_slice(&mut adr[..]).ok();
    socket.recv_slice(&mut len[..]).ok();
    let adr = u32::from_le_bytes(adr);
    let len = u32::from_le_bytes(len);
    (adr, len as usize)
}

/// Check if address+length is valid for read/write flash.
fn check_address_valid(address: u32, length: usize) -> Result<()> {
    if address > (FLASH_END - length as u32 + 1) {
        Err(Error::InvalidAddress)
    } else {
        Ok(())
    }
}

/// Check length is a multiple of 4 and no greater than 1024
fn check_length_valid(length: usize) -> Result<()> {
    if length % 4 != 0 {
        Err(Error::LengthNotMultiple4)
    } else if length > 2048 {
        Err(Error::LengthTooLong)
    } else {
        Ok(())
    }
}

/// Check the specified length matches the amount of data available
fn check_length_correct(length: usize, data: &[u8]) -> Result<()> {
    if length != data.len() {
        Err(Error::DataLengthIncorrect)
    } else {
        Ok(())
    }
}

/// Send a status word back at the start of a response
fn send_status(socket: &mut TcpSocket, status: Error) {
    let resp = (status as u32).to_le_bytes();
    socket.send_slice(&resp).unwrap();
}

/// Try to get the FLASH peripheral
fn get_flash_peripheral() -> Result<&'static mut device::FLASH> {
    match unsafe { FLASH.as_mut() } {
        Some(flash) => Ok(flash),
        None => Err(Error::InternalError),
    }
}

/// Try to unlock flash
fn unlock(flash: &mut device::FLASH) -> Result<()> {
    // Wait for any ongoing operations
    while flash.sr.read().bsy().bit_is_set() {}

    // Attempt unlock
    flash.keyr.write(|w| w.key().bits(0x45670123));
    flash.keyr.write(|w| w.key().bits(0xCDEF89AB));

    // Verify success
    match flash.cr.read().lock().is_unlocked() {
        true => Ok(()),
        false => Err(Error::FlashError),
    }
}

/// Lock flash
fn lock(flash: &mut device::FLASH) {
    flash.cr.write(|w| w.lock().locked());
}

/// Write to flash.
/// Returns () on success, None on failure.
/// length must be a multiple of 4.
pub fn write(address: u32, length: usize, data: &[u8]) -> Result<()> {
    check_address_valid(address, length)?;
    check_length_valid(length)?;
    check_length_correct(length, data)?;

    let flash = get_flash_peripheral()?;
    unlock(flash)?;

    // Set parallelism to write in 32 bit chunks, and enable programming.
    // Note reset value has 1 for lock so we need to explicitly clear it.
    flash
        .cr
        .write(|w| w.lock().unlocked().psize().psize32().pg().program());

    for idx in 0..(length / 4) {
        let offset = idx * 4;
        let word: u32 = (data[offset] as u32)
            | (data[offset + 1] as u32) << 8
            | (data[offset + 2] as u32) << 16
            | (data[offset + 3] as u32) << 24;
        let write_address = (address + offset as u32) as *mut u32;
        unsafe { core::ptr::write_volatile(write_address, word) };

        // Wait for write
        while flash.sr.read().bsy().bit_is_set() {}

        // Check for errors
        let sr = flash.sr.read();
        if sr.pgperr().bit_is_set() || sr.pgaerr().bit_is_set() || sr.wrperr().bit_is_set() {
            lock(flash);
            return Err(Error::WriteError);
        }
    }

    lock(flash);
    Ok(())
}

fn cmd_write(socket: &mut TcpSocket) {
    let (adr, len) = read_adr_len(socket);
    match socket.recv(|buf| (buf.len(), write(adr, len, buf))) {
        Ok(Ok(())) => send_status(socket, Error::Success),
        Ok(Err(err)) => send_status(socket, err),
        Err(_) => send_status(socket, Error::NetworkError),
    }
}

pub fn cmd_erase(socket: &mut TcpSocket) {
    let (adr, len) = read_adr_len(socket);
    match erase(adr, len) {
        Ok(()) => send_status(socket, Error::Success),
        Err(err) => send_status(socket, err),
    }
}

/// Erase flash sectors that cover the given address and length.
pub fn erase(address: u32, length: usize) -> Result<()> {
    check_address_valid(address, length)?;
    let address_start = address;
    let address_end = address + length as u32;
    // writeln!(stdout, "addr {} , end {}", address_start, address_end).unwrap();
    for (idx, sector_start) in FLASH_SECTOR_ADDRESSES.iter().enumerate() {
        let sector_start = *sector_start;
        let sector_end = match FLASH_SECTOR_ADDRESSES.get(idx + 1) {
            Some(adr) => *adr - 1,
            None => FLASH_END,
        };
        if (address_start >= sector_start && address_start <= sector_end)
            || (address_end >= sector_start && address_end <= sector_end)
            || (address_start <= sector_start && address_end >= sector_end)
        {
            erase_sector(idx as u8)?;
        }
    }
    Ok(())
}

/// Erase specified sector
fn erase_sector(sector: u8) -> Result<()> {
    if (sector as usize) >= FLASH_SECTOR_ADDRESSES.len() {
        return Err(Error::InternalError);
    }
    let flash = get_flash_peripheral()?;
    unlock(flash)?;

    // Erase.
    // UNSAFE: We've verified that `sector`<FLASH_SECTOR_ADDRESSES.len(),
    // which is is the number of sectors.
    unsafe {
        flash
            .cr
            .write(|w| w.lock().unlocked().ser().sector_erase().snb().bits(sector));
        flash.cr.modify(|_, w| w.strt().start());
    }

    // Wait
    while flash.sr.read().bsy().bit_is_set() {}

    // Check for errors
    let sr = flash.sr.read();

    // Re-lock flash
    lock(flash);

    if sr.wrperr().bit_is_set() {
        Err(Error::EraseError)
    } else {
        // writeln!(stdout, "Erasing Sector done..").unwrap();
        Ok(())
    }
}

